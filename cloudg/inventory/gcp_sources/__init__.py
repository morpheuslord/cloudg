"""API-backed GCP sources for what Cloud Asset Inventory does not return.

The deep GCP collector (:class:`~cloudg.inventory.gcp_deep.GCPDeepInventoryCollector`)
runs these from its ``_enrich()`` hook, each one best-effort with its own
coverage record (``gcp_<name>``) and filtered by ``inventory.services`` /
``inventory.exclude_services`` like the AWS tasks:

=========================  ===========  ==================================================
Source                     Family       What it maps
=========================  ===========  ==================================================
cloud_identity             identity     Google groups and memberships (Cloud Identity)
iam_deny                   identity     IAM deny policies (POLICY_DENIES_ACTION)
principal_access_boundary  identity     PAB policies and bindings (PERMISSION_BOUNDARY_LIMITS)
pam                        identity     Privileged Access Manager entitlements
iam_roles                  identity     Bound predefined roles and their permissions
scc                        security     Security Command Center tier, services, sources, exports
artifact_analysis          security     Vulnerability occurrences per container image
iam_recommender            security     IAM role recommendations (FINDING_AFFECTS)
dlp_discovery              security     "Not enabled" placeholders for SDP discovery
audit_configs              logging      Data Access audit log configs (IAM policy auditConfigs)
monitoring                 logging      Alert policies, channels, uptime checks, metrics scopes
dns_records                dns          Cloud DNS record sets (DNS_RESOLVED)
os_config                  ops          Patch deployments, OS policies, VM vulnerability reports
cloud_scheduler            integration  Cloud Scheduler jobs (SCHEDULED_BY)
backup_dr                  backup       Backup and DR vaults, plans, associations
firestore_backups          backup       Firestore backups and backup schedules
apigee                     serverless   Apigee target servers and proxy deployments
infra_manager              iac          Resources Infrastructure Manager deployments manage
deployment_manager         iac          Deployment Manager deployments and their resources
=========================  ===========  ==================================================

All REST calls go through :class:`~cloudg.inventory.gcp_sources.rest.GCPRestClient`
(google-auth ``AuthorizedSession``), which tests replace with a fake transport.
"""

from __future__ import annotations

# Source modules: imported for their registration side effect.
from cloudg.inventory.gcp_sources import identity, ops, platform, security  # noqa: F401
from cloudg.inventory.gcp_sources.base import (
    SOURCES,
    GCPSourceOptions,
    Source,
    SourceContext,
    SourceRun,
    SourceSkipped,
    run_sources,
    source,
)
from cloudg.inventory.gcp_sources.rest import GCPApiError, GCPRestClient

__all__ = [
    "GCPApiError",
    "GCPRestClient",
    "GCPSourceOptions",
    "SOURCES",
    "Source",
    "SourceContext",
    "SourceRun",
    "SourceSkipped",
    "run_sources",
    "source",
]
