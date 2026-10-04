"""Deep GCP inventory collector.

The base :class:`GCPCollector` enumerates every resource with Cloud Asset
Inventory ``ListAssets`` (full resource JSON) and declares typed relations
through :mod:`cloudg.inventory.gcp_relations`. This subclass deepens the map:

- A much richer GCP-type -> normalised AssetType mapping, so resources
  classify as real asset types instead of OTHER.
- IAM policy bindings via ``SearchAllIamPolicies``: every member becomes a
  principal asset (the collected service account, or a non-external
  ``gcp-principal:<member>`` placeholder) carrying GRANTS_ACCESS /
  ASSUMES_ROLE relations to the bound resource. ``allUsers`` and
  ``allAuthenticatedUsers`` mark the resource internet-exposed.

Edges are resolved by the inventory mapper's linker, so this collector
does not link locally.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.collectors.gcp import _GCP_ASSET_TYPE_MAP, GCPCollector
from cloudg.coverage import ServiceStatus
from cloudg.inventory.gcp_relations import apply_iam_policies, merge_gcp_principals
from cloudg.schema.models import AssetType, CloudAsset

logger = logging.getLogger(__name__)

__all__ = ["GCPDeepInventoryCollector", "_DEEP_GCP_TYPE_MAP", "merge_gcp_principals"]

_C = "compute.googleapis.com/"

# Deep mapping adds to the base table (catalogs/gcp_asset_types.yaml, "deep").
_DEEP_GCP_TYPE_MAP: dict[str, AssetType] = {
    **_GCP_ASSET_TYPE_MAP,
    **asset_type_map(load_catalog("gcp_asset_types").get("deep"), "gcp_asset_types"),
}


class GCPDeepInventoryCollector(GCPCollector):
    """GCP collector with a deeper type taxonomy and IAM-binding relations."""

    _link_locally_default = False

    def _resolve_asset_type(self, gcp_type: str) -> AssetType:
        return _DEEP_GCP_TYPE_MAP.get(gcp_type, AssetType.OTHER)

    def _search_iam(self) -> tuple[list[dict[str, Any]], Exception | None]:
        client = self._get_client()
        request = {"scope": self._scope, "page_size": 500}
        return self._iterate(client.search_all_iam_policies, request)

    def _keep_policy(self, pol: dict[str, Any]) -> bool:
        if not self._project_filter:
            return True
        project = str(pol.get("project") or "")
        if not project:
            return True
        number = project.removeprefix("projects/")
        return bool({number, self._number_to_id.get(number)} & self._project_filter)

    async def _enrich(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        if not self._include_iam:
            return []
        start = time.time()
        policies, error = await asyncio.to_thread(self._search_iam)
        policies = [p for p in policies if isinstance(p, dict) and self._keep_policy(p)]
        if error is not None:
            logger.error("GCP IAM policy search failed for %s: %s", self._scope, error)
            status = ServiceStatus.PARTIAL if policies else ServiceStatus.FAILED
            self._record("gcp_iam_policies", status, len(policies), str(error), start=start)
        else:
            self._record("gcp_iam_policies", ServiceStatus.SUCCESS, len(policies), start=start)
        created = apply_iam_policies(assets, policies)
        logger.info("GCP IAM: %d policies, %d new principal assets", len(policies), len(created))
        return created
