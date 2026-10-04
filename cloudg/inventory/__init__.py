"""Scanner-independent infrastructure inventory mapping.

This package maps everything deployed (or default) in a cloud account and
how it interlinks — without running any security scanner — across every
account of an AWS Organization / Control Tower landing zone when asked.
Its output can later be merged with scanner findings to build asset and
compliance maps, and queried for interdependencies (DependencyGraph).
"""

from cloudg.inventory.aws_deep import AWSDeepInventoryCollector
from cloudg.inventory.azure_deep import AzureDeepInventoryCollector
from cloudg.inventory.gcp_deep import GCPDeepInventoryCollector
from cloudg.inventory.dependencies import DependencyGraph
from cloudg.inventory.linker import RelationshipLinker
from cloudg.inventory.mapper import InventoryMapper, InventoryResult
from cloudg.inventory.organization import OrganizationTopology, discover_organization

__all__ = [
    "AWSDeepInventoryCollector",
    "AzureDeepInventoryCollector",
    "DependencyGraph",
    "GCPDeepInventoryCollector",
    "InventoryMapper",
    "InventoryResult",
    "OrganizationTopology",
    "RelationshipLinker",
    "discover_organization",
]
