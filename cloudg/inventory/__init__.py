"""Scanner-independent infrastructure inventory mapping.

This package maps everything deployed (or default) in a cloud account and
how it interlinks — without running any security scanner. Its output can
later be merged with scanner findings to build asset and compliance maps.
"""

from cloudg.inventory.aws_deep import AWSDeepInventoryCollector
from cloudg.inventory.azure_deep import AzureDeepInventoryCollector
from cloudg.inventory.gcp_deep import GCPDeepInventoryCollector
from cloudg.inventory.linker import RelationshipLinker
from cloudg.inventory.mapper import InventoryMapper, InventoryResult

__all__ = [
    "AWSDeepInventoryCollector",
    "AzureDeepInventoryCollector",
    "GCPDeepInventoryCollector",
    "InventoryMapper",
    "InventoryResult",
    "RelationshipLinker",
]
