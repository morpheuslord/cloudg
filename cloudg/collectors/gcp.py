"""GCP resource collector using google-cloud-asset SDK."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.collectors.base import BaseCollector
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)

logger = logging.getLogger(__name__)

# Mapping from GCP asset types to our normalised AssetType
_GCP_ASSET_TYPE_MAP: dict[str, AssetType] = {
    "compute.googleapis.com/Instance": AssetType.GCE_INSTANCE,
    "compute.googleapis.com/Network": AssetType.VPC,
    "compute.googleapis.com/Subnetwork": AssetType.SUBNET,
    "compute.googleapis.com/Firewall": AssetType.SECURITY_GROUP,
    "compute.googleapis.com/ForwardingRule": AssetType.LOAD_BALANCER,
    "compute.googleapis.com/Address": AssetType.ELASTIC_IP,
    "compute.googleapis.com/Router": AssetType.NAT_GATEWAY,
    "storage.googleapis.com/Bucket": AssetType.GCS_BUCKET,
    "sqladmin.googleapis.com/Instance": AssetType.CLOUD_SQL,
    "cloudfunctions.googleapis.com/Function": AssetType.CLOUD_FUNCTION,
    "container.googleapis.com/Cluster": AssetType.GKE_CLUSTER,
    "iam.googleapis.com/ServiceAccount": AssetType.SERVICE_PRINCIPAL,
    "cloudkms.googleapis.com/CryptoKey": AssetType.KMS_KEY,
    "secretmanager.googleapis.com/Secret": AssetType.SECRET,
}


class GCPCollector(BaseCollector):
    """Collects GCP resources using the Cloud Asset Inventory API.

    Uses search_all_resources() for efficient batch inventory.
    """

    def __init__(
        self,
        project_id: str,
        credentials: Any = None,
    ) -> None:
        self._project_id = project_id
        self._credentials = credentials
        self._cached_assets: list[CloudAsset] = []

    def _resolve_asset_type(self, gcp_type: str) -> AssetType:
        """Map GCP asset type string to normalised AssetType."""
        return _GCP_ASSET_TYPE_MAP.get(gcp_type, AssetType.OTHER)

    def _extract_location(self, name: str) -> str:
        """Extract region/zone from resource name."""
        parts = name.split("/")
        # Pattern: projects/X/zones/ZONE/... or projects/X/regions/REGION/...
        for i, part in enumerate(parts):
            if part in ("zones", "regions", "locations") and i + 1 < len(parts):
                return parts[i + 1]
        return "global"

    async def collect(self) -> list[CloudAsset]:
        """Collect all GCP assets via Cloud Asset Inventory."""
        logger.info("Starting GCP asset collection for project %s", self._project_id)
        assets: list[CloudAsset] = []

        try:
            from google.cloud import asset_v1

            client = asset_v1.AssetServiceClient(credentials=self._credentials)
            scope = f"projects/{self._project_id}"

            # Search all resources in the project
            request = asset_v1.SearchAllResourcesRequest(scope=scope)
            results = client.search_all_resources(request=request)

            for resource in results:
                asset_type = self._resolve_asset_type(resource.asset_type)
                location = resource.location or self._extract_location(resource.name)

                # Extract labels as tags
                tags = dict(resource.labels) if resource.labels else {}

                assets.append(
                    CloudAsset(
                        arn=resource.name,
                        name=resource.display_name or resource.name.split("/")[-1],
                        asset_type=asset_type,
                        provider=CloudProvider.GCP,
                        region=location,
                        account_id=self._project_id,
                        tags=tags,
                        metadata={
                            "gcp_asset_type": resource.asset_type,
                            "project": resource.project,
                            "description": resource.description,
                            "state": resource.state.name if resource.state else None,
                            "parent_asset_type": resource.parent_asset_type,
                            "parent_full_resource_name": resource.parent_full_resource_name,
                            "network_tags": list(resource.network_tags) if resource.network_tags else [],
                        },
                        raw_data={
                            "name": resource.name,
                            "asset_type": resource.asset_type,
                        },
                    )
                )

            logger.info("Collected %d GCP assets", len(assets))

        except ImportError:
            logger.warning(
                "google-cloud-asset not installed, skipping GCP collection. "
                "Install with: pip install google-cloud-asset"
            )
        except Exception as exc:
            logger.error("Failed to collect GCP assets: %s", exc)

        self._cached_assets = assets
        return assets

    async def collect_edges(self) -> list[NetworkEdge]:
        """Collect GCP network edges from firewall rules and containment."""
        assets = self._cached_assets or await self.collect()
        edges: list[NetworkEdge] = []

        # Containment: VPC → Subnet
        vpc_map: dict[str, str] = {}
        for asset in assets:
            if asset.asset_type == AssetType.VPC:
                vpc_map[asset.arn or asset.id] = asset.id

        for asset in assets:
            if asset.asset_type == AssetType.SUBNET:
                # GCP subnet names contain network reference
                network = asset.metadata.get("parent_full_resource_name")
                if network and network in vpc_map:
                    edges.append(
                        NetworkEdge(
                            source_id=vpc_map[network],
                            target_id=asset.id,
                            edge_type=EdgeType.CONTAINS,
                        )
                    )

        # Firewall rules as security group edges
        for asset in assets:
            if asset.asset_type == AssetType.SECURITY_GROUP:
                # GCP firewall rules have network_tags for targeting
                network_tags = asset.metadata.get("network_tags", [])
                for tag in network_tags:
                    edges.append(
                        NetworkEdge(
                            source_id="0.0.0.0/0",
                            target_id=asset.id,
                            edge_type=EdgeType.SECURITY_GROUP_RULE,
                            cidr="0.0.0.0/0",
                            direction="ingress",
                            description=f"GCP firewall rule targeting tag: {tag}",
                        )
                    )

        logger.info("Collected %d GCP edges", len(edges))
        return edges
