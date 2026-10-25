"""Azure parity: in-cluster AKS mapping through the Kubernetes API."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import yaml

from cloudg.inventory.azure_kubernetes import (
    aks_mappable,
    cluster_endpoint,
    collect_aks_workloads,
)
from cloudg.schema.models import CloudProvider
from tests.test_azure_inventory import SUB

RG = f"/subscriptions/{SUB}/resourceGroups/rg-k8s"
AKS = f"{RG}/providers/Microsoft.ContainerService/managedClusters/aks-entra"
SERVER = "https://aks-entra-dns.hcp.westeurope.azmk8s.io:443"


def _kubeconfig() -> str:
    config = {
        "clusters": [
            {
                "name": "aks-entra",
                "cluster": {"server": SERVER, "certificate-authority-data": "Q0E="},
            }
        ],
        "users": [{"name": "clusterUser", "user": {"exec": {"command": "kubelogin"}}}],
    }
    return base64.b64encode(yaml.safe_dump(config).encode()).decode()


class _Arm:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def post(self, path, api_version=None, body=None):
        self.calls.append(("post", path))
        return self.routes[path]


class FakeReader:
    def __init__(self):
        self.items = {
            "/api/v1/namespaces": [{"metadata": {"name": "orders"}}],
            "/api/v1/serviceaccounts": [
                {
                    "metadata": {
                        "name": "api",
                        "namespace": "orders",
                        "annotations": {"azure.workload.identity/client-id": "CLIENT-API"},
                    }
                }
            ],
            "/api/v1/services": [
                {
                    "metadata": {"name": "api", "namespace": "orders"},
                    "spec": {"type": "LoadBalancer", "selector": {"app": "api"}},
                    "status": {"loadBalancer": {"ingress": [{"ip": "20.30.40.50"}]}},
                }
            ],
        }

    def list(self, path):
        return iter(self.items.get(path, []))


class Credential:
    def get_token(self, scope):
        return SimpleNamespace(token="entra-token", expires_on=9999999999)


def test_cluster_endpoint_reads_only_the_clusters_section():
    arm = _Arm({f"{AKS}/listClusterUserCredential": {"kubeconfigs": [{"value": _kubeconfig()}]}})
    assert cluster_endpoint(arm, AKS) == (SERVER, "Q0E=")
    assert arm.calls[0][0] == "post"


def test_mappable_needs_entra_integration():
    assert (
        aks_mappable({"properties": {}}) == "no Microsoft Entra integration (local accounts only)"
    )
    assert aks_mappable({"properties": {"aadProfile": {"managed": True}}}) is None


def test_collect_aks_workloads_direct():
    arm = _Arm({f"{AKS}/listClusterUserCredential": {"kubeconfigs": [{"value": _kubeconfig()}]}})
    cluster = {"id": AKS, "location": "westeurope", "subscriptionId": SUB, "properties": {}}
    assets = collect_aks_workloads(
        Credential(), arm, cluster, reader_factory=lambda s, c, t, to: FakeReader()
    )
    by_arn = {a.arn: a for a in assets}
    sa = by_arn[f"k8s://{AKS}/orders/ServiceAccount/api"]
    assert sa.provider == CloudProvider.AZURE and sa.region == "westeurope"
    assert sa.metadata["workload_identity_client_id"] == "CLIENT-API"
    identity = [r for r in sa.metadata["relations"] if r["edge"] == "ASSUMES_ROLE"]
    assert identity[0]["target"] == "azure-client-id:client-api"
    svc = by_arn[f"k8s://{AKS}/orders/Service/api"]
    assert svc.metadata["load_balancer_hostnames"] == ["20.30.40.50"]
    assert svc.is_internet_exposed
