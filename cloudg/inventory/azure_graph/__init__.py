"""Azure Resource Graph collection and relation extraction.

Azure Resource Graph (ARG) returns every resource of a subscription with
its full ``properties`` bag in a handful of paginated KQL queries, which is
both far faster and far richer than enumerating each service SDK. This
package holds the provider-neutral half of the Azure inventory:

- :func:`run_query` (``query``): paginated ARG queries (``skipToken``)
  with 429 back-off, against any client exposing ``resources(request)``.
- :class:`AzureAssetBuilder` (``builder``): turns ARM-shaped rows (from
  ARG *or* from SDK models serialised with :func:`to_rest`) into
  :class:`CloudAsset` objects carrying typed ``metadata["relations"]`` and
  ``metadata["aliases"]`` for the
  :class:`~cloudg.inventory.linker.RelationshipLinker`.
- An extractor registry (``registry``) keyed by lowercase ARM resource
  type. Every row goes through the common extractors (identity, managedBy,
  parent / resource-group containment, private endpoint connections, PaaS
  exposure) and then the type-specific ones, which live in one module per
  service area and register themselves on import below.

Identifier conventions are documented in :mod:`.helpers`.
"""

from __future__ import annotations

# Importing the extractor modules registers their extractors.
from cloudg.inventory.azure_graph import (  # noqa: F401
    compute,
    data_security,
    edge,
    network,
    web_containers,
)
from cloudg.inventory.azure_graph.arm_types import _ARM_TYPE_MAP, asset_type_from_arm
from cloudg.inventory.azure_graph.builder import (
    AzureAssetBuilder,
    build_assets,
    collect_subscription_graph,
)
from cloudg.inventory.azure_graph.helpers import (
    _GUID_TAIL_RE,
    _MAX_LIST,
    _MAX_STR,
    _MG_RE,
    _REDACT_KEYS,
    _RG_RE,
    _SUB_RE,
    ACR_PULL_ROLE_ID,
    BUILTIN_ROLES,
    LOG_ANALYTICS_PREFIX,
    PRINCIPAL_PREFIX,
    PRIVILEGED_ROLES,
    _docker_image,
    _get,
    _kql,
    _lower,
    _list,
    _path,
    _props,
    _rid,
    _rids,
    _segments,
    _tags,
    host_of,
    management_group_ref,
    normalize_scope,
    owner_resource_id,
    parent_resource_id,
    principal_ref,
    registry_host,
    resource_group_name,
    resource_group_of,
    sanitize,
    subscription_of,
    subscription_ref,
    to_rest,
)
from cloudg.inventory.azure_graph.query import (
    QueryLimits,
    _make_request,
    _rows_of,
    _status_code,
    containers_query,
    default_graph_client_factory,
    defender_query,
    resources_query,
    role_assignments_query,
    run_query,
)
from cloudg.inventory.azure_graph.registry import (
    _COMMON,
    _EXTRACTORS,
    _PARENT_RELATIONSHIP,
    Extractor,
    _Draft,
    _keyvault_key_ref,
    _network_rule_grants,
    _set_exposure,
    extractor,
)

__all__ = [
    "ACR_PULL_ROLE_ID",
    "BUILTIN_ROLES",
    "LOG_ANALYTICS_PREFIX",
    "PRINCIPAL_PREFIX",
    "PRIVILEGED_ROLES",
    "QueryLimits",
    "AzureAssetBuilder",
    "Extractor",
    "_ARM_TYPE_MAP",
    "_COMMON",
    "_Draft",
    "_EXTRACTORS",
    "_GUID_TAIL_RE",
    "_MAX_LIST",
    "_MAX_STR",
    "_MG_RE",
    "_PARENT_RELATIONSHIP",
    "_REDACT_KEYS",
    "_RG_RE",
    "_SUB_RE",
    "_docker_image",
    "_get",
    "_keyvault_key_ref",
    "_kql",
    "_list",
    "_lower",
    "_make_request",
    "_network_rule_grants",
    "_path",
    "_props",
    "_rid",
    "_rids",
    "_rows_of",
    "_segments",
    "_set_exposure",
    "_status_code",
    "_tags",
    "asset_type_from_arm",
    "build_assets",
    "collect_subscription_graph",
    "containers_query",
    "default_graph_client_factory",
    "defender_query",
    "extractor",
    "host_of",
    "management_group_ref",
    "normalize_scope",
    "owner_resource_id",
    "parent_resource_id",
    "principal_ref",
    "registry_host",
    "resource_group_name",
    "resource_group_of",
    "resources_query",
    "role_assignments_query",
    "run_query",
    "sanitize",
    "subscription_of",
    "subscription_ref",
    "to_rest",
]
