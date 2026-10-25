"""Azure parity: in-cluster AKS mapping through the Kubernetes API."""

from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace

import yaml

from cloudg.coverage import ServiceStatus
from cloudg.inventory.azure_deep import AzureDeepInventoryCollector
from cloudg.inventory.azure_kubernetes import AKS_SCOPE, aks_mappable, cluster_endpoint
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, CloudProvider, EdgeType
from tests.azure_fakes import FakeArm, TypedFakeGraph
from tests.test_azure_inventory import SUB, _Graph, _row

RG = f"/subscriptions/{SUB}/resourceGroups/rg-k8s"
AKS = f"{RG}/providers/Microsoft.ContainerService/managedClusters/aks-entra"
AKS_LOCAL = f"{RG}/providers/Microsoft.ContainerService/managedClusters/aks-local"
ACR = f"{RG}/providers/Microsoft.ContainerRegistry/registries/acrk8s"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-api"
PIP = f"{RG}/providers/Microsoft.Network/publicIPAddresses/kubernetes-lb"
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


class FakeReader:
    def __init__(self):
        self.paths = []
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
            "/apis/apps/v1/deployments": [
                {
                    "metadata": {"name": "api", "namespace": "orders"},
                    "spec": {
                        "replicas": 2,
                        "template": {
                            "metadata": {"labels": {"app": "api"}},
                            "spec": {
                                "serviceAccountName": "api",
                                "containers": [
                                    {"name": "api", "image": "acrk8s.azurecr.io/orders/api:1.4"}
                                ],
                            },
                        },
                    },
                }
            ],
            "/api/v1/services": [
                {
                    "metadata": {"name": "api", "namespace": "orders"},
                    "spec": {
                        "type": "LoadBalancer",
                        "selector": {"app": "api"},
                        "ports": [{"port": 443}],
                    },
                    "status": {"loadBalancer": {"ingress": [{"ip": "20.30.40.50"}]}},
                }
            ],
        }

    def list(self, path):
        self.paths.append(path)
        return iter(self.items.get(path, []))


class Credential:
    def __init__(self):
        self.scopes = []

    def get_token(self, scope):
        self.scopes.append(scope)
        return SimpleNamespace(token="entra-token", expires_on=9999999999)


def _resources():
    return [
        _row(
            AKS,
            "microsoft.containerservice/managedclusters",
            {"aadProfile": {"managed": True, "enableAzureRBAC": True}},
        ),
        _row(AKS_LOCAL, "microsoft.containerservice/managedclusters", {}),
        _row(ACR, "microsoft.containerregistry/registries", {"loginServer": "acrk8s.azurecr.io"}),
        _row(
            UAMI,
            "microsoft.managedidentity/userassignedidentities",
            {"clientId": "client-api", "principalId": "p"},
        ),
        _row(PIP, "microsoft.network/publicipaddresses", {"ipAddress": "20.30.40.50"}),
    ]


def test_cluster_endpoint_reads_only_the_clusters_section():
    arm = FakeArm(
        {
            f"{AKS}/listClusterUserCredential": {
                "kubeconfigs": [{"name": "clusterUser", "value": _kubeconfig()}]
            }
        }
    )
    assert cluster_endpoint(arm, AKS) == (SERVER, "Q0E=")
    assert arm.calls[0][0] == "post"


def test_mappable_needs_entra_integration():
    assert (
        aks_mappable({"properties": {}}) == "no Microsoft Entra integration (local accounts only)"
    )
    assert aks_mappable({"properties": {"aadProfile": {"managed": True}}}) is None


def test_aks_workloads_mapped_like_eks():
    arm = FakeArm({f"{AKS}/listClusterUserCredential": {"kubeconfigs": [{"value": _kubeconfig()}]}})
    reader = FakeReader()
    seen = {}

    def reader_factory(server, ca, token, timeout):
        seen.update(server=server, ca=ca, token=token)
        return reader

    cred = Credential()
    collector = AzureDeepInventoryCollector(
        cred,
        SUB,
        graph_client_factory=lambda c: TypedFakeGraph({"resources": _resources()}),
        arm_client_factory=lambda c: arm,
        dataplane_client_factory=lambda c, b, s: FakeArm({}),
        services=["containers", "identity", "network"],
    )
    collector.aks_reader_factory = reader_factory
    assets = asyncio.run(collector.collect())
    cov = {s.service: s for s in collector.coverage.services}
    assert cov["kubernetes:aks-entra"].status == ServiceStatus.SUCCESS
    assert cov["kubernetes:aks-entra"].asset_count == 4
    assert cov["kubernetes:aks-local"].status == ServiceStatus.SKIPPED
    assert AKS_SCOPE in cred.scopes
    assert seen == {"server": SERVER, "ca": "Q0E=", "token": "entra-token"}

    linker = RelationshipLinker(assets)
    edges = linker.link()
    g = _Graph(assets + linker.external_assets, edges)
    ns = f"k8s://{AKS}/_cluster/Namespace/orders"
    sa = f"k8s://{AKS}/orders/ServiceAccount/api"
    deploy = f"k8s://{AKS}/orders/Deployment/api"
    svc = f"k8s://{AKS}/orders/Service/api"
    assert g.a(deploy).asset_type == AssetType.K8S_WORKLOAD
    assert g.a(deploy).provider == CloudProvider.AZURE
    assert g.has(AKS, ns, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE")
    assert g.has(deploy, ACR, EdgeType.USES_IMAGE, "RUNS_ON")
    assert g.has(deploy, sa, EdgeType.REFERENCES, "RUNS_ON")
    # Entra Workload ID: the service account runs as the user-assigned identity
    assert g.has(sa, UAMI, EdgeType.ASSUMES_ROLE, "RUNS_ON")
    assert g.has(svc, deploy, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
    # the load balancer IP is the public IP resource
    assert g.has(PIP, svc, EdgeType.ROUTE, "LOAD_BALANCED_BY")
    assert g.a(svc).is_internet_exposed


def test_unreachable_cluster_is_failed_not_fatal():
    arm = FakeArm({})  # listClusterUserCredential refused (404)
    collector = AzureDeepInventoryCollector(
        Credential(),
        SUB,
        graph_client_factory=lambda c: TypedFakeGraph({"resources": _resources()}),
        arm_client_factory=lambda c: arm,
        dataplane_client_factory=lambda c, b, s: FakeArm({}),
    )
    assets = asyncio.run(collector.collect())
    cov = {s.service: s for s in collector.coverage.services}
    assert cov["kubernetes:aks-entra"].status == ServiceStatus.FAILED
    assert any(a.arn == AKS for a in assets)


def test_kubernetes_opt_out():
    collector = AzureDeepInventoryCollector(
        Credential(),
        SUB,
        graph_client_factory=lambda c: TypedFakeGraph({"resources": _resources()}),
        arm_client_factory=lambda c: FakeArm({}),
        kubernetes=False,
    )
    asyncio.run(collector.collect())
    cov = {s.service: s for s in collector.coverage.services}
    assert cov["aks_kubernetes"].status == ServiceStatus.SKIPPED
    assert "kubernetes:aks-entra" not in cov

    excluded = AzureDeepInventoryCollector(
        Credential(),
        SUB,
        graph_client_factory=lambda c: TypedFakeGraph({"resources": _resources()}),
        arm_client_factory=lambda c: FakeArm({}),
        exclude_services=["kubernetes"],
    )
    asyncio.run(excluded.collect())
    cov = {s.service: s for s in excluded.coverage.services}
    assert cov["aks_kubernetes"].status == ServiceStatus.SKIPPED


def test_collect_aks_workloads_direct():
    from cloudg.inventory.azure_kubernetes import collect_aks_workloads

    arm = FakeArm({f"{AKS}/listClusterUserCredential": {"kubeconfigs": [{"value": _kubeconfig()}]}})
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
