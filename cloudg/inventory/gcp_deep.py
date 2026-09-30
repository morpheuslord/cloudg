"""Deep GCP inventory collector.

The base :class:`GCPCollector` already enumerates **every** resource in a
project via the Cloud Asset Inventory ``search_all_resources`` API, so
coverage is complete by construction. This subclass deepens the map:

- A much richer GCP-type → normalised AssetType mapping, so sweep hits
  classify as real asset types instead of OTHER.
- IAM policy bindings via ``search_all_iam_policies``, turned into
  IAM_POLICY_ATTACHMENT edges (identity → resource) so access paths show
  up on the inventory map.
"""

from __future__ import annotations

import logging

from cloudg.collectors.gcp import _GCP_ASSET_TYPE_MAP, GCPCollector
from cloudg.schema.models import AssetType, EdgeType, NetworkEdge

logger = logging.getLogger(__name__)

_DEEP_GCP_TYPE_MAP: dict[str, AssetType] = {
    **_GCP_ASSET_TYPE_MAP,
    "compute.googleapis.com/Disk": AssetType.EBS_VOLUME,
    "compute.googleapis.com/Route": AssetType.ROUTE_TABLE,
    "compute.googleapis.com/VpnGateway": AssetType.TRANSIT_GATEWAY,
    "compute.googleapis.com/InstanceGroup": AssetType.OTHER,
    "compute.googleapis.com/BackendService": AssetType.LOAD_BALANCER,
    "compute.googleapis.com/TargetHttpProxy": AssetType.LOAD_BALANCER,
    "compute.googleapis.com/TargetHttpsProxy": AssetType.LOAD_BALANCER,
    "compute.googleapis.com/UrlMap": AssetType.LOAD_BALANCER,
    "run.googleapis.com/Service": AssetType.CLOUD_FUNCTION,
    "cloudfunctions.googleapis.com/CloudFunction": AssetType.CLOUD_FUNCTION,
    "appengine.googleapis.com/Application": AssetType.APP_SERVICE,
    "appengine.googleapis.com/Service": AssetType.APP_SERVICE,
    "bigquery.googleapis.com/Dataset": AssetType.OTHER,
    "bigquery.googleapis.com/Table": AssetType.OTHER,
    "bigtableadmin.googleapis.com/Instance": AssetType.DYNAMODB_TABLE,
    "firestore.googleapis.com/Database": AssetType.DYNAMODB_TABLE,
    "spanner.googleapis.com/Instance": AssetType.CLOUD_SQL,
    "redis.googleapis.com/Instance": AssetType.OTHER,
    "pubsub.googleapis.com/Topic": AssetType.OTHER,
    "pubsub.googleapis.com/Subscription": AssetType.OTHER,
    "dns.googleapis.com/ManagedZone": AssetType.OTHER,
    "iam.googleapis.com/Role": AssetType.IAM_ROLE,
    "cloudkms.googleapis.com/KeyRing": AssetType.KMS_KEY,
    "logging.googleapis.com/LogSink": AssetType.CLOUDTRAIL,
    "monitoring.googleapis.com/AlertPolicy": AssetType.OTHER,
    "artifactregistry.googleapis.com/Repository": AssetType.OTHER,
    "cloudresourcemanager.googleapis.com/Project": AssetType.OTHER,
}


class GCPDeepInventoryCollector(GCPCollector):
    """GCP collector with a deeper type taxonomy and IAM-binding edges."""

    def _resolve_asset_type(self, gcp_type: str) -> AssetType:
        return _DEEP_GCP_TYPE_MAP.get(gcp_type, AssetType.OTHER)

    async def _collect_iam_binding_edges(self) -> list[NetworkEdge]:
        """IAM policy bindings as identity → resource attachment edges."""
        edges: list[NetworkEdge] = []
        try:
            from google.cloud import asset_v1

            client = asset_v1.AssetServiceClient(credentials=self._credentials)
            scope = f"projects/{self._project_id}"
            request = asset_v1.SearchAllIamPoliciesRequest(scope=scope)
            results = client.search_all_iam_policies(request=request)

            asset_by_name = {
                a.arn: a.id for a in self._cached_assets if a.arn
            }
            for result in results:
                resource_name = result.resource
                target = asset_by_name.get(resource_name, resource_name)
                policy = result.policy
                for binding in policy.bindings if policy else []:
                    for member in binding.members:
                        edges.append(
                            NetworkEdge(
                                source_id=member,
                                target_id=target,
                                edge_type=EdgeType.IAM_POLICY_ATTACHMENT,
                                description=f"{member} has {binding.role}",
                            )
                        )
        except ImportError:
            logger.warning("google-cloud-asset not installed, skipping IAM bindings")
        except Exception as exc:
            logger.error("Failed to collect GCP IAM bindings: %s", exc)
        return edges

    async def collect_edges(self) -> list[NetworkEdge]:
        edges = await super().collect_edges()
        edges.extend(await self._collect_iam_binding_edges())
        logger.info("Deep GCP inventory: %d edges", len(edges))
        return edges
