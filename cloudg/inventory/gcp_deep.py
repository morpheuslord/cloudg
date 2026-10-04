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
    "compute.googleapis.com/InstanceGroupManager": AssetType.AUTOSCALING_GROUP,
    "compute.googleapis.com/InstanceTemplate": AssetType.LAUNCH_TEMPLATE,
    "compute.googleapis.com/SecurityPolicy": AssetType.WAF_WEB_ACL,
    "compute.googleapis.com/ForwardingRule": AssetType.LOAD_BALANCER,
    "container.googleapis.com/NodePool": AssetType.NODE_GROUP,
    "k8s.io/Namespace": AssetType.K8S_NAMESPACE,
    "k8s.io/Service": AssetType.K8S_SERVICE,
    "k8s.io/ServiceAccount": AssetType.K8S_SERVICE_ACCOUNT,
    "apps.k8s.io/Deployment": AssetType.K8S_WORKLOAD,
    "apps.k8s.io/StatefulSet": AssetType.K8S_WORKLOAD,
    "apps.k8s.io/DaemonSet": AssetType.K8S_WORKLOAD,
    "batch.k8s.io/CronJob": AssetType.K8S_WORKLOAD,
    "networking.k8s.io/Ingress": AssetType.K8S_INGRESS,
    "extensions.k8s.io/Ingress": AssetType.K8S_INGRESS,
    "file.googleapis.com/Instance": AssetType.FILE_SYSTEM,
    "workflows.googleapis.com/Workflow": AssetType.STATE_MACHINE,
    "apigateway.googleapis.com/Gateway": AssetType.API_GATEWAY,
    "eventarc.googleapis.com/Trigger": AssetType.EVENT_RULE,
    "cloudscheduler.googleapis.com/Job": AssetType.EVENT_RULE,
    "logging.googleapis.com/LogBucket": AssetType.LOG_GROUP,
    "cloudresourcemanager.googleapis.com/Folder": AssetType.ORG_UNIT,
    "cloudresourcemanager.googleapis.com/Organization": AssetType.ORGANIZATION,
    "compute.googleapis.com/BackendService": AssetType.LOAD_BALANCER,
    "compute.googleapis.com/TargetHttpProxy": AssetType.LOAD_BALANCER,
    "compute.googleapis.com/TargetHttpsProxy": AssetType.LOAD_BALANCER,
    "compute.googleapis.com/UrlMap": AssetType.LOAD_BALANCER,
    "run.googleapis.com/Service": AssetType.CLOUD_FUNCTION,
    "cloudfunctions.googleapis.com/CloudFunction": AssetType.CLOUD_FUNCTION,
    "appengine.googleapis.com/Application": AssetType.APP_SERVICE,
    "appengine.googleapis.com/Service": AssetType.APP_SERVICE,
    "bigquery.googleapis.com/Dataset": AssetType.DATA_WAREHOUSE,
    "bigquery.googleapis.com/Table": AssetType.OTHER,
    "bigtableadmin.googleapis.com/Instance": AssetType.DYNAMODB_TABLE,
    "firestore.googleapis.com/Database": AssetType.DYNAMODB_TABLE,
    "spanner.googleapis.com/Instance": AssetType.CLOUD_SQL,
    "redis.googleapis.com/Instance": AssetType.CACHE_CLUSTER,
    "pubsub.googleapis.com/Topic": AssetType.NOTIFICATION_TOPIC,
    "pubsub.googleapis.com/Subscription": AssetType.MESSAGE_QUEUE,
    "dns.googleapis.com/ManagedZone": AssetType.DNS_ZONE,
    "iam.googleapis.com/Role": AssetType.IAM_ROLE,
    "cloudkms.googleapis.com/KeyRing": AssetType.KMS_KEY,
    "logging.googleapis.com/LogSink": AssetType.CLOUDTRAIL,
    "monitoring.googleapis.com/AlertPolicy": AssetType.OTHER,
    "artifactregistry.googleapis.com/Repository": AssetType.CONTAINER_REGISTRY,
    "cloudresourcemanager.googleapis.com/Project": AssetType.CLOUD_ACCOUNT,
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
