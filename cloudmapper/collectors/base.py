"""Abstract base collector for all cloud providers."""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloudmapper.schema.models import CloudAsset, NetworkEdge


class BaseCollector(abc.ABC):
    """Abstract base class for cloud resource collectors.

    Each provider-specific collector must implement:
    - collect(): enumerate all cloud assets
    - collect_edges(): enumerate network/IAM relationships
    """

    @abc.abstractmethod
    async def collect(self) -> list[CloudAsset]:
        """Collect all cloud assets from the provider.

        Returns:
            A list of CloudAsset objects representing discovered resources.
        """

    @abc.abstractmethod
    async def collect_edges(self) -> list[NetworkEdge]:
        """Collect all network and IAM relationship edges.

        Returns:
            A list of NetworkEdge objects representing connectivity.
        """

    async def run(self) -> tuple[list[CloudAsset], list[NetworkEdge]]:
        """Convenience: collect assets and edges together.

        Returns:
            Tuple of (assets, edges).
        """
        assets = await self.collect()
        edges = await self.collect_edges()
        return assets, edges
