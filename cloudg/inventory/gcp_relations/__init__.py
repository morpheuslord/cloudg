"""Relation extractors for GCP Cloud Asset Inventory resources.

Each extractor reads the full resource JSON that ``list_assets`` returns
(``resource.data``) for one CAI asset type and declares what the asset
talks to as ``metadata["relations"]`` entries built with :func:`rel`. The
:class:`~cloudg.inventory.linker.RelationshipLinker` later resolves the
targets against every collected asset and emits typed edges.

GCP references come in several shapes: compute selfLinks
(``https://www.googleapis.com/compute/v1/projects/p/...``), API URLs,
relative names (``projects/p/locations/l/...``), short names, and service
account emails. They are all normalised here, before they reach a
relation, to the CAI full resource name form
``//<service>.googleapis.com/<relative name>``, which is what the linker
treats as an identifier. Service accounts are referenced as
``serviceAccount:<email>`` (an alias on every service account asset).

Identity conventions:

- IAM principals that are not collected resources become assets with
  ``arn = "gcp-principal:<member>"`` (users, groups, domains, federated
  principals) so bindings never create ``is_external`` graph nodes.
- GKE workload identity Kubernetes service accounts use
  ``k8s-gke://<workload-pool-project>/<namespace>/<ksa>``.

The package is split by service area; importing it imports every extractor
module so each one registers its CAI asset types in :data:`EXTRACTORS`.
"""

from __future__ import annotations

# Extractor modules: imported for their registration side effect.
from cloudg.inventory.gcp_relations import (  # noqa: F401
    compute,
    data_logging,
    gke,
    load_balancing,
    messaging,
    network,
    pipelines,
    resource_manager,
    serverless,
)
from cloudg.inventory.gcp_relations.context import (
    EXTRACTORS,
    Extracted,
    Extractor,
    GCPContext,
    extract,
    mark_exposed,
)
from cloudg.inventory.gcp_relations.iam import (
    apply_iam_policies,
    ensure_service_account_principals,
    ksa_identifier,
    merge_gcp_principals,
    principal_asset,
    principal_identifier,
    principal_kind,
)
from cloudg.inventory.gcp_relations.names import (
    IMPERSONATION_ROLES,
    INTERNET_CIDRS,
    K8S_GKE_PREFIX,
    PRINCIPAL_PREFIX,
    PUBLIC_MEMBERS,
    REDACTED,
    SA_ASSET_TYPE,
    dig,
    full_name,
    image_repository,
    kms_refs,
    network_ref,
    project_of,
    relative_name,
    sa_email,
    sa_ref,
    scrub,
    subnet_ref,
    url_alias,
)
from cloudg.inventory.gcp_relations.resource_manager import perimeter_metadata

__all__ = [
    "EXTRACTORS",
    "IMPERSONATION_ROLES",
    "INTERNET_CIDRS",
    "K8S_GKE_PREFIX",
    "PRINCIPAL_PREFIX",
    "PUBLIC_MEMBERS",
    "REDACTED",
    "SA_ASSET_TYPE",
    "Extracted",
    "Extractor",
    "GCPContext",
    "apply_iam_policies",
    "dig",
    "ensure_service_account_principals",
    "extract",
    "full_name",
    "image_repository",
    "kms_refs",
    "ksa_identifier",
    "mark_exposed",
    "merge_gcp_principals",
    "network_ref",
    "perimeter_metadata",
    "principal_asset",
    "principal_identifier",
    "principal_kind",
    "project_of",
    "relative_name",
    "sa_email",
    "sa_ref",
    "scrub",
    "subnet_ref",
    "url_alias",
]
