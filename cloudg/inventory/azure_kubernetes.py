"""Read-only in-cluster mapping for AKS, the same way EKS clusters are mapped.

For each AKS cluster with Microsoft Entra integration, cloudg:

1. reads the cluster API server URL and CA certificate from the user
   kubeconfig ARM returns for ``listClusterUserCredential`` (a read-only
   list action; for Entra-integrated clusters the kubeconfig holds no
   secret, and only the ``clusters`` section is ever parsed),
2. requests an Entra token for the AKS server application
   (``6dae42f8-4368-4678-94ff-3960e28e3630/.default``) from the same
   azure-identity credential, exactly what ``kubelogin`` does, and
3. reads namespaces, workloads, services, ingresses and service accounts
   with :func:`cloudg.inventory.kubernetes.map_cluster_objects`, issuing
   only ``GET`` requests with TLS verified against the cluster CA.

The identity needs Azure Kubernetes Service RBAC Reader (Azure RBAC
clusters) or a Kubernetes ``view`` binding. Clusters with local accounts
only (no Entra integration) are skipped: their credentials are secrets.
Private clusters are tried and reported FAILED when the API server is not
reachable from where cloudg runs. ``az aks command invoke`` is not used:
it starts a pod in the cluster, which is not read-only.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Callable

import yaml

from cloudg.inventory.azure_graph.helpers import _get, _path
from cloudg.inventory.kubernetes import KubernetesReader, map_cluster_objects
from cloudg.schema.models import CloudAsset, CloudProvider

logger = logging.getLogger(__name__)

AKS_SERVER_APP_ID = "6dae42f8-4368-4678-94ff-3960e28e3630"
AKS_SCOPE = f"{AKS_SERVER_APP_ID}/.default"
_AKS_API = "2024-05-01"


def cluster_endpoint(arm: Any, cluster_id: str) -> tuple[str, str | None]:
    """(API server URL, base64 CA bundle) from the cluster's user kubeconfig."""
    data = arm.post(f"{cluster_id}/listClusterUserCredential", _AKS_API)
    for entry in data.get("kubeconfigs") or []:
        raw = entry.get("value")
        if not raw:
            continue
        config = yaml.safe_load(base64.b64decode(raw).decode("utf-8")) or {}
        for cluster in config.get("clusters") or []:
            spec = cluster.get("cluster") or {}
            server = spec.get("server")
            if server:
                return str(server), spec.get("certificate-authority-data")
    raise ValueError("no API server in the cluster kubeconfig")


def aks_mappable(cluster: dict[str, Any]) -> str | None:
    """Why a cluster cannot be read in-cluster (None when it can)."""
    props = cluster.get("properties") or {}
    if not _get(props, "aadProfile"):
        return "no Microsoft Entra integration (local accounts only)"
    if _lower_state(_path(props, "powerState", "code")) == "stopped":
        return "cluster is stopped"
    return None


def _lower_state(value: Any) -> str:
    return str(value or "").lower()


def collect_aks_workloads(
    credential: Any,
    arm: Any,
    cluster: dict[str, Any],
    *,
    timeout: int = 10,
    reader_factory: Callable[[str, str | None, str, int], Any] | None = None,
) -> list[CloudAsset]:
    """Map the Kubernetes objects of one AKS cluster (blocking; run in a thread).

    Args:
        credential: azure-identity TokenCredential.
        arm: ARM REST client (``post(path, api_version)``).
        cluster: The cluster row (``id``, ``location``, ``subscriptionId``, ``properties``).
        reader_factory: ``(server, ca_b64, token, timeout) -> reader`` (tests).
    """
    server, ca = cluster_endpoint(arm, cluster["id"])
    token = credential.get_token(AKS_SCOPE).token
    factory = reader_factory or (lambda s, c, t, to: KubernetesReader(s, c, t, timeout=to))
    reader = factory(server, ca, token, timeout)
    return map_cluster_objects(
        reader,
        cluster["id"],
        cluster.get("location") or "global",
        cluster.get("subscriptionId"),
        provider=CloudProvider.AZURE,
    )


__all__ = ["AKS_SCOPE", "aks_mappable", "cluster_endpoint", "collect_aks_workloads"]
