"""Tests for the GCP inventory mapper (Cloud Asset Inventory based).

A fake AssetServiceClient serves ListAssets / SearchAllResources /
SearchAllIamPolicies results as plain dicts (the shape ``Asset.to_dict``
produces) or real proto-plus messages.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cloudg.collectors.gcp import GCPCollector
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.graph.builder import GraphBuilder
from cloudg.inventory.gcp_deep import _DEEP_GCP_TYPE_MAP, GCPDeepInventoryCollector
from cloudg.inventory.gcp_hierarchy import discover_gcp_hierarchy
from cloudg.inventory.gcp_relations import (
    full_name,
    image_repository,
    merge_gcp_principals,
    principal_asset,
)
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

PROJECT = "proj-a"
NUMBER = "111"
ANC = [f"projects/{NUMBER}", "folders/555", "organizations/999"]
CRM = "//cloudresourcemanager.googleapis.com/"
C = "//compute.googleapis.com/projects/proj-a/"
SL = "https://www.googleapis.com/compute/v1/projects/proj-a/"
APP_SA = "app@proj-a.iam.gserviceaccount.com"
KEY = "//cloudkms.googleapis.com/projects/proj-a/locations/us/keyRings/r/cryptoKeys/k"


def res(name: str, asset_type: str, data: dict[str, Any], location: str = "", ancestors=None, parent: str = "") -> dict:
    return {
        "name": name,
        "asset_type": asset_type,
        "resource": {"data": data, "location": location, "parent": parent or f"{CRM}projects/{NUMBER}"},
        "ancestors": list(ANC if ancestors is None else ancestors),
    }


class FakeAssetClient:
    def __init__(
        self,
        resources=(),
        iam=(),
        search=(),
        org_policies=(),
        access=(),
        list_error: Exception | None = None,
        list_error_after: int | None = None,
        search_error: Exception | None = None,
    ) -> None:
        self.resources = list(resources)
        self.iam = list(iam)
        self.search = list(search)
        self.org_policies = list(org_policies)
        self.access = list(access)
        self.list_error = list_error
        self.list_error_after = list_error_after
        self.search_error = search_error
        self.requests: list[tuple[str, dict]] = []

    def list_assets(self, request=None, **kwargs):
        self.requests.append(("list_assets", request))
        assert "retry" in kwargs and "timeout" in kwargs
        ct = getattr(request["content_type"], "name", request["content_type"])
        if ct == "RESOURCE":
            if self.list_error is not None and self.list_error_after is None:
                raise self.list_error
            items = self.resources
            if request.get("asset_types"):
                items = [i for i in items if i["asset_type"] in request["asset_types"]]
            return self._gen(items, self.list_error_after, self.list_error)
        if ct == "ORG_POLICY":
            return iter(self.org_policies)
        if ct == "ACCESS_POLICY":
            return iter(self.access)
        return iter([])

    @staticmethod
    def _gen(items, fail_after, error):
        for i, item in enumerate(items):
            if fail_after is not None and i >= fail_after:
                raise error
            yield item

    def search_all_resources(self, request=None, **kwargs):
        self.requests.append(("search_all_resources", request))
        if self.search_error is not None:
            raise self.search_error
        return iter(self.search)

    def search_all_iam_policies(self, request=None, **kwargs):
        self.requests.append(("search_all_iam_policies", request))
        return iter(self.iam)


def run(coro):
    return asyncio.run(coro)


def _collect(collector):
    assets = run(collector.collect())
    edges = run(collector.collect_edges())
    linker = RelationshipLinker(assets)
    linker.seed_existing(edges)
    edges = edges + linker.link()
    return assets, edges, linker


def by_arn(assets: list[CloudAsset], arn: str) -> CloudAsset:
    matches = [a for a in assets if a.arn == arn]
    assert matches, f"no asset {arn}"
    return matches[0]


def has_edge(edges, src: CloudAsset, dst: CloudAsset, edge_type: EdgeType, relationship: str | None = None) -> bool:
    return any(
        e.source_id == src.id
        and e.target_id == dst.id
        and e.edge_type == edge_type
        and (relationship is None or e.relationship == relationship)
        for e in edges
    )


# ---------------------------------------------------------------------------
# Fixture inventory
# ---------------------------------------------------------------------------

PROJECT_ASSET = res(
    f"{CRM}projects/{NUMBER}",
    "cloudresourcemanager.googleapis.com/Project",
    {"projectNumber": NUMBER, "projectId": PROJECT, "lifecycleState": "ACTIVE", "parent": {"type": "folder", "id": "555"}},
    location="global",
    parent=f"{CRM}folders/555",
)
NETWORK = res(C + "global/networks/vpc1", "compute.googleapis.com/Network", {"name": "vpc1", "selfLink": SL + "global/networks/vpc1"}, "global")
SUBNET = res(
    C + "regions/us-central1/subnetworks/sn1",
    "compute.googleapis.com/Subnetwork",
    {"name": "sn1", "network": SL + "global/networks/vpc1", "ipCidrRange": "10.0.0.0/24"},
    "us-central1",
)
SERVICE_ACCOUNT = res(
    "//iam.googleapis.com/projects/proj-a/serviceAccounts/1234567890",
    "iam.googleapis.com/ServiceAccount",
    {"email": APP_SA, "uniqueId": "1234567890", "projectId": PROJECT, "name": f"projects/proj-a/serviceAccounts/{APP_SA}"},
    "global",
)
DEFAULT_SA = res(
    "//iam.googleapis.com/projects/proj-a/serviceAccounts/42",
    "iam.googleapis.com/ServiceAccount",
    {"email": f"{NUMBER}-compute@developer.gserviceaccount.com", "uniqueId": "42", "projectId": PROJECT},
    "global",
)
KMS_KEY = res(KEY, "cloudkms.googleapis.com/CryptoKey", {"purpose": "ENCRYPT_DECRYPT"}, "us")
DISK = res(
    C + "zones/us-central1-a/disks/vm1",
    "compute.googleapis.com/Disk",
    {
        "name": "vm1",
        "users": [SL + "zones/us-central1-a/instances/vm1"],
        "diskEncryptionKey": {"kmsKeyName": "projects/proj-a/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3"},
    },
    "us-central1-a",
)
VM_WEB = res(
    C + "zones/us-central1-a/instances/vm1",
    "compute.googleapis.com/Instance",
    {
        "name": "vm1",
        "status": "RUNNING",
        "serviceAccounts": [{"email": APP_SA, "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
        "networkInterfaces": [
            {
                "network": SL + "global/networks/vpc1",
                "subnetwork": SL + "regions/us-central1/subnetworks/sn1",
                "networkIP": "10.0.0.2",
                "accessConfigs": [{"natIP": "34.1.2.3"}],
            }
        ],
        "disks": [{"source": SL + "zones/us-central1-a/disks/vm1", "boot": True}],
        "tags": {"items": ["web"]},
        "metadata": {"items": [{"key": "startup-script", "value": "export DB_PASSWORD=hunter2"}]},
        "labels": {"env": "prod"},
    },
    "us-central1-a",
)
VM_DB = res(
    C + "zones/us-central1-a/instances/vm2",
    "compute.googleapis.com/Instance",
    {
        "name": "vm2",
        "status": "RUNNING",
        "networkInterfaces": [{"network": SL + "global/networks/vpc1", "subnetwork": SL + "regions/us-central1/subnetworks/sn1"}],
        "tags": {"items": ["db"]},
    },
    "us-central1-a",
)
FW_WEB = res(
    C + "global/firewalls/allow-web",
    "compute.googleapis.com/Firewall",
    {
        "name": "allow-web",
        "network": SL + "global/networks/vpc1",
        "direction": "INGRESS",
        "priority": 1000,
        "sourceRanges": ["0.0.0.0/0"],
        "targetTags": ["web"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
    },
    "global",
)
FW_DB = res(
    C + "global/firewalls/allow-ssh-db",
    "compute.googleapis.com/Firewall",
    {
        "name": "allow-ssh-db",
        "network": SL + "global/networks/vpc1",
        "direction": "INGRESS",
        "sourceRanges": ["0.0.0.0/0"],
        "targetTags": ["db"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    },
    "global",
)
FW_DISABLED = res(
    C + "global/firewalls/allow-all-disabled",
    "compute.googleapis.com/Firewall",
    {
        "name": "allow-all-disabled",
        "network": SL + "global/networks/vpc1",
        "direction": "INGRESS",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "all"}],
        "disabled": True,
    },
    "global",
)
AR_REPO = res(
    "//artifactregistry.googleapis.com/projects/proj-a/locations/us-central1/repositories/repo1",
    "artifactregistry.googleapis.com/Repository",
    {"format": "DOCKER"},
    "us-central1",
)
SECRET = res("//secretmanager.googleapis.com/projects/111/secrets/db-pass", "secretmanager.googleapis.com/Secret", {"replication": {"automatic": {}}}, "global")
CONNECTOR = res(
    "//vpcaccess.googleapis.com/projects/proj-a/locations/us-central1/connectors/conn1",
    "vpcaccess.googleapis.com/Connector",
    {"network": "vpc1", "subnet": {"name": "sn1"}},
    "us-central1",
)
RUN_SVC = res(
    "//run.googleapis.com/projects/proj-a/locations/us-central1/services/api",
    "run.googleapis.com/Service",
    {
        "kind": "Service",
        "metadata": {"name": "api", "annotations": {"run.googleapis.com/ingress": "all"}},
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "run.googleapis.com/vpc-access-connector": "conn1",
                        "run.googleapis.com/cloudsql-instances": "proj-a:us-central1:db1",
                    }
                },
                "spec": {
                    "serviceAccountName": "run-sa@proj-a.iam.gserviceaccount.com",
                    "containers": [
                        {
                            "image": "us-central1-docker.pkg.dev/proj-a/repo1/api@sha256:abc",
                            "env": [
                                {"name": "DB_PASS", "valueFrom": {"secretKeyRef": {"name": "db-pass", "key": "latest"}}},
                                {"name": "PLAIN", "value": "hunter2"},
                            ],
                        }
                    ],
                },
            }
        },
        "status": {"url": "https://api-xyz-uc.a.run.app"},
    },
    "us-central1",
)
CLOUD_SQL = res(
    "//cloudsql.googleapis.com/projects/proj-a/instances/db1",
    "sqladmin.googleapis.com/Instance",
    {
        "databaseVersion": "POSTGRES_15",
        "settings": {
            "ipConfiguration": {
                "ipv4Enabled": True,
                "authorizedNetworks": [{"value": "0.0.0.0/0"}],
                "privateNetwork": "projects/proj-a/global/networks/vpc1",
            }
        },
    },
    "us-central1",
)
TOPIC = res("//pubsub.googleapis.com/projects/proj-a/topics/t1", "pubsub.googleapis.com/Topic", {"name": "projects/proj-a/topics/t1"}, "global")
SUBSCRIPTION = res(
    "//pubsub.googleapis.com/projects/proj-a/subscriptions/s1",
    "pubsub.googleapis.com/Subscription",
    {
        "name": "projects/proj-a/subscriptions/s1",
        "topic": "projects/proj-a/topics/t1",
        "pushConfig": {
            "pushEndpoint": "https://api-xyz-uc.a.run.app/push?token=supersecret",
            "oidcToken": {"serviceAccountEmail": APP_SA},
        },
    },
    "global",
)
BUCKET_PUBLIC = res("//storage.googleapis.com/static-bkt", "storage.googleapis.com/Bucket", {"name": "static-bkt"}, "us")
BUCKET_LOGS = res("//storage.googleapis.com/audit-logs", "storage.googleapis.com/Bucket", {"name": "audit-logs"}, "us")
DATASET = res("//bigquery.googleapis.com/projects/proj-a/datasets/logs_ds", "bigquery.googleapis.com/Dataset", {"access": []}, "US")
SINK_GCS = res(
    "//logging.googleapis.com/projects/proj-a/sinks/audit",
    "logging.googleapis.com/LogSink",
    {
        "name": "audit",
        "destination": "storage.googleapis.com/audit-logs",
        "writerIdentity": "serviceAccount:service-111@gcp-sa-logging.iam.gserviceaccount.com",
        "filter": "logName:cloudaudit.googleapis.com",
    },
    "global",
)
SINK_BQ = res(
    "//logging.googleapis.com/projects/proj-a/sinks/to-bq",
    "logging.googleapis.com/LogSink",
    {"name": "to-bq", "destination": "bigquery.googleapis.com/projects/proj-a/datasets/logs_ds"},
    "global",
)
# Load-balancer chain: forwarding rule -> HTTPS proxy -> URL map -> backend service -> serverless NEG -> Cloud Run
FR = res(
    C + "global/forwardingRules/fr1",
    "compute.googleapis.com/GlobalForwardingRule",
    {
        "name": "fr1",
        "IPAddress": "34.9.9.9",
        "IPProtocol": "TCP",
        "portRange": "443-443",
        "loadBalancingScheme": "EXTERNAL_MANAGED",
        "target": SL + "global/targetHttpsProxies/proxy1",
    },
    "global",
)
PROXY = res(
    C + "global/targetHttpsProxies/proxy1",
    "compute.googleapis.com/TargetHttpsProxy",
    {"urlMap": SL + "global/urlMaps/um1", "sslCertificates": [SL + "global/sslCertificates/cert1"]},
    "global",
)
URL_MAP = res(
    C + "global/urlMaps/um1",
    "compute.googleapis.com/UrlMap",
    {
        "defaultService": SL + "global/backendServices/bs1",
        "pathMatchers": [{"name": "static", "defaultService": SL + "global/backendBuckets/bb1"}],
    },
    "global",
)
BACKEND = res(
    C + "global/backendServices/bs1",
    "compute.googleapis.com/BackendService",
    {
        "backends": [{"group": SL + "regions/us-central1/networkEndpointGroups/neg1"}],
        "securityPolicy": SL + "global/securityPolicies/armor1",
        "loadBalancingScheme": "EXTERNAL_MANAGED",
    },
    "global",
)
NEG = res(
    C + "regions/us-central1/networkEndpointGroups/neg1",
    "compute.googleapis.com/NetworkEndpointGroup",
    {"networkEndpointType": "SERVERLESS", "cloudRun": {"service": "api"}},
    "us-central1",
)
BACKEND_BUCKET = res(C + "global/backendBuckets/bb1", "compute.googleapis.com/BackendBucket", {"bucketName": "static-bkt"}, "global")
ARMOR = res(C + "global/securityPolicies/armor1", "compute.googleapis.com/SecurityPolicy", {"rules": [{}]}, "global")
CERT = res(C + "global/sslCertificates/cert1", "compute.googleapis.com/SslCertificate", {"type": "MANAGED"}, "global")
ADDRESS = res(
    C + "global/addresses/addr1",
    "compute.googleapis.com/GlobalAddress",
    {"address": "34.9.9.9", "addressType": "EXTERNAL", "users": [SL + "global/forwardingRules/fr1"]},
    "global",
)
# GKE
GKE = res(
    "//container.googleapis.com/projects/proj-a/locations/us-central1/clusters/gke1",
    "container.googleapis.com/Cluster",
    {
        "name": "gke1",
        "network": "vpc1",
        "networkConfig": {
            "network": "projects/proj-a/global/networks/vpc1",
            "subnetwork": "projects/proj-a/regions/us-central1/subnetworks/sn1",
        },
        "nodeConfig": {"serviceAccount": "default"},
        "privateClusterConfig": {"enablePrivateNodes": True},
        "masterAuthorizedNetworksConfig": {"enabled": False},
        "workloadIdentityConfig": {"workloadPool": "proj-a.svc.id.goog"},
        "databaseEncryption": {"state": "ENCRYPTED", "keyName": "projects/proj-a/locations/us/keyRings/r/cryptoKeys/k"},
        "masterAuth": {"clientKey": "PRIVATE"},
    },
    "us-central1",
)
NODE_POOL = res(
    "//container.googleapis.com/projects/proj-a/locations/us-central1/clusters/gke1/nodePools/np1",
    "container.googleapis.com/NodePool",
    {
        "config": {"serviceAccount": APP_SA},
        "instanceGroupUrls": [SL + "zones/us-central1-a/instanceGroupManagers/gke-gke1-np1-grp"],
    },
    "us-central1",
)
IGM = res(
    C + "zones/us-central1-a/instanceGroupManagers/gke-gke1-np1-grp",
    "compute.googleapis.com/InstanceGroupManager",
    {
        "instanceTemplate": SL + "global/instanceTemplates/gke-tmpl",
        "instanceGroup": SL + "zones/us-central1-a/instanceGroups/gke-gke1-np1-grp",
    },
    "us-central1-a",
)
IG = res(C + "zones/us-central1-a/instanceGroups/gke-gke1-np1-grp", "compute.googleapis.com/InstanceGroup", {"size": 3}, "us-central1-a")
POD = res(
    "//container.googleapis.com/projects/proj-a/locations/us-central1/clusters/gke1/k8s/namespaces/ns1/pods/p1",
    "k8s.io/Pod",
    {"metadata": {"name": "p1"}},
    "us-central1",
)

ALL_RESOURCES = [
    PROJECT_ASSET, NETWORK, SUBNET, SERVICE_ACCOUNT, DEFAULT_SA, KMS_KEY, DISK, VM_WEB, VM_DB,
    FW_WEB, FW_DB, FW_DISABLED, AR_REPO, SECRET, CONNECTOR, RUN_SVC, CLOUD_SQL, TOPIC,
    SUBSCRIPTION, BUCKET_PUBLIC, BUCKET_LOGS, DATASET, SINK_GCS, SINK_BQ, FR, PROXY, URL_MAP,
    BACKEND, NEG, BACKEND_BUCKET, ARMOR, CERT, ADDRESS, GKE, NODE_POOL, IGM, IG, POD,
]

SA_RESOURCE = f"//iam.googleapis.com/projects/proj-a/serviceAccounts/{APP_SA}"
IAM_POLICIES = [
    {
        "resource": f"{CRM}projects/{NUMBER}",
        "project": f"projects/{NUMBER}",
        "policy": {
            "bindings": [
                {
                    "role": "roles/editor",
                    "members": [
                        "user:alice@example.com",
                        f"serviceAccount:{APP_SA}",
                        "group:devs@example.com",
                        "domain:example.com",
                        "deleted:user:old@example.com?uid=1",
                    ],
                },
                {"role": "roles/viewer", "members": ["user:alice@example.com"], "condition": {"title": "business hours"}},
            ]
        },
    },
    {
        "resource": "//storage.googleapis.com/static-bkt",
        "policy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
    },
    {
        "resource": SA_RESOURCE,
        "policy": {
            "bindings": [
                {"role": "roles/iam.workloadIdentityUser", "members": ["serviceAccount:proj-a.svc.id.goog[ns1/ksa1]"]},
                {"role": "roles/iam.serviceAccountTokenCreator", "members": ["user:alice@example.com"]},
            ]
        },
    },
    {
        "resource": "//run.googleapis.com/projects/proj-a/locations/us-central1/services/api",
        "policy": {
            "bindings": [
                {
                    "role": "roles/run.invoker",
                    "members": [
                        "principalSet://iam.googleapis.com/projects/111/locations/global/workloadIdentityPools/gh/attribute.repository/org/repo"
                    ],
                }
            ]
        },
    },
]


@pytest.fixture(scope="module")
def mapped():
    client = FakeAssetClient(resources=ALL_RESOURCES, iam=IAM_POLICIES)
    collector = GCPDeepInventoryCollector(PROJECT, credentials=None, client=client)
    assets, edges, linker = _collect(collector)
    return {"assets": assets, "edges": edges, "linker": linker, "client": client, "collector": collector}


# ---------------------------------------------------------------------------
# P0: state string / failure visibility
# ---------------------------------------------------------------------------


class TestEnumeration:
    def test_list_assets_request_and_full_data(self, mapped):
        client, assets = mapped["client"], mapped["assets"]
        kind, request = client.requests[0]
        assert kind == "list_assets"
        assert request["parent"] == f"projects/{PROJECT}"
        assert getattr(request["content_type"], "name", request["content_type"]) == "RESOURCE"
        assert request["page_size"] == 1000
        vm = by_arn(assets, VM_WEB["name"])
        assert vm.metadata["state"] == "RUNNING"
        assert vm.account_id == PROJECT
        assert vm.metadata["project_number"] == NUMBER
        assert vm.metadata["folders"] == ["folders/555"]
        assert vm.metadata["organization"] == "organizations/999"
        assert vm.tags == {"env": "prod"}
        assert vm.raw_data["data"]["name"] == "vm1"
        assert vm.metadata["parent_full_resource_name"] == f"{CRM}projects/{NUMBER}"
        assert vm.asset_type == AssetType.GCE_INSTANCE

    def test_secrets_never_stored(self, mapped):
        for a in mapped["assets"]:
            blob = repr(a.metadata) + repr(a.raw_data)
            assert "hunter2" not in blob
            assert "supersecret" not in blob
            assert "PRIVATE" not in blob or a.asset_type != AssetType.GKE_CLUSTER

    def test_pods_skipped_by_default(self, mapped):
        assert not any(a.arn == POD["name"] for a in mapped["assets"])

    def test_search_fallback_handles_string_state(self):
        from google.api_core import exceptions as gexc
        from google.cloud import asset_v1

        search = [
            asset_v1.ResourceSearchResult(
                name=f"{C}zones/z/instances/i{n}",
                asset_type="compute.googleapis.com/Instance",
                state="RUNNING",
                project=f"projects/{NUMBER}",
                location="us-central1-a",
                labels={"team": "x"},
            )
            for n in range(3)
        ]
        cov = CollectionCoverage(provider="gcp")
        client = FakeAssetClient(search=search, list_error=gexc.PermissionDenied("listResource denied"))
        assets = run(GCPCollector(PROJECT, client=client, coverage=cov).collect())
        instances = [a for a in assets if a.asset_type == AssetType.GCE_INSTANCE]
        assert len(instances) == 3  # the first state no longer aborts the loop
        assert all(a.metadata["state"] == "RUNNING" for a in instances)
        assert all(a.account_id == PROJECT for a in instances)
        statuses = {s.service: s.status for s in cov.services}
        assert statuses["gcp_list_assets"] == ServiceStatus.FAILED
        assert statuses["gcp_search_resources"] == ServiceStatus.PARTIAL

    def test_total_failure_raises(self):
        from google.api_core import exceptions as gexc

        client = FakeAssetClient(
            list_error=gexc.PermissionDenied("denied"), search_error=gexc.PermissionDenied("denied")
        )
        with pytest.raises(RuntimeError, match="enumeration failed"):
            run(GCPCollector(PROJECT, client=client).collect())

    def test_truncated_listing_is_partial(self):
        from google.api_core import exceptions as gexc

        cov = CollectionCoverage(provider="gcp")
        client = FakeAssetClient(
            resources=[NETWORK, SUBNET, VM_DB], list_error=gexc.InternalServerError("boom"), list_error_after=2
        )
        assets = run(GCPCollector(PROJECT, client=client, coverage=cov).collect())
        assert any(a.arn == SUBNET["name"] for a in assets)
        assert {s.service: s.status for s in cov.services}["gcp_list_assets"] == ServiceStatus.PARTIAL

    def test_type_map(self):
        assert "cloudscheduler.googleapis.com/Job" not in _DEEP_GCP_TYPE_MAP
        assert _DEEP_GCP_TYPE_MAP["cloudkms.googleapis.com/KeyRing"] != AssetType.KMS_KEY
        assert _DEEP_GCP_TYPE_MAP["compute.googleapis.com/Router"] == AssetType.ROUTER
        assert _DEEP_GCP_TYPE_MAP["run.googleapis.com/Service"] == AssetType.CONTAINER_SERVICE
        assert _DEEP_GCP_TYPE_MAP["compute.googleapis.com/VpnTunnel"] == AssetType.VPN_CONNECTION
        assert _DEEP_GCP_TYPE_MAP["logging.googleapis.com/LogSink"] == AssetType.LOG_SINK


# ---------------------------------------------------------------------------
# P0: IAM members
# ---------------------------------------------------------------------------


class TestIAM:
    def test_no_external_placeholder_nodes(self, mapped):
        graph = GraphBuilder().build(mapped["assets"], mapped["edges"])
        external = [n for n, d in graph.nodes(data=True) if d.get("is_external")]
        assert external == ["0.0.0.0/0"]

    def test_service_account_member_resolves_to_sa_asset(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        sa = by_arn(assets, SERVICE_ACCOUNT["name"])
        project = by_arn(assets, f"{CRM}projects/{NUMBER}")
        assert has_edge(edges, sa, project, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION")
        assert not any(a.arn == f"gcp-principal:serviceAccount:{APP_SA}" for a in assets)

    def test_principal_placeholders(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        project = by_arn(assets, f"{CRM}projects/{NUMBER}")
        alice = by_arn(assets, "gcp-principal:user:alice@example.com")
        assert alice.asset_type == AssetType.IDENTITY_USER
        assert alice.name == "user:alice@example.com"
        assert by_arn(assets, "gcp-principal:group:devs@example.com").asset_type == AssetType.IDENTITY_GROUP
        domain = by_arn(assets, "gcp-principal:domain:example.com")
        assert domain.asset_type == AssetType.IDENTITY_GROUP
        assert domain.metadata["principal_type"] == "domain"
        assert not any("old@example.com" in (a.arn or "") for a in assets)
        grant = [e for e in edges if e.source_id == alice.id and e.target_id == project.id]
        assert len(grant) == 1 and grant[0].edge_type == EdgeType.GRANTS_ACCESS
        assert grant[0].properties["roles"] == ["roles/editor", "roles/viewer"]
        assert grant[0].properties["condition"] == "business hours"
        assert not alice.is_internet_exposed and not project.is_internet_exposed

    def test_federated_principal_set(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        ps = [a for a in assets if (a.arn or "").startswith("gcp-principal:principalSet://")]
        assert len(ps) == 1 and ps[0].asset_type == AssetType.IDENTITY_PROVIDER
        run_svc = by_arn(assets, RUN_SVC["name"])
        assert has_edge(edges, ps[0], run_svc, EdgeType.GRANTS_ACCESS)

    def test_all_users_marks_resource_exposed(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        bucket = by_arn(assets, BUCKET_PUBLIC["name"])
        assert bucket.is_internet_exposed
        assert bucket.metadata["public_access"] == [{"member": "allUsers", "role": "roles/storage.objectViewer"}]
        assert any(e.source_id == "0.0.0.0/0" and e.target_id == bucket.id for e in edges)
        assert not any(a.name in ("allUsers", "allAuthenticatedUsers") for a in assets)

    def test_impersonation_and_workload_identity(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        sa = by_arn(assets, SERVICE_ACCOUNT["name"])
        ksa = by_arn(assets, "k8s-gke://proj-a/ns1/ksa1")
        assert ksa.asset_type == AssetType.K8S_SERVICE_ACCOUNT
        assert has_edge(edges, ksa, sa, EdgeType.ASSUMES_ROLE, "ROLE_ASSUMES_ROLE")
        alice = by_arn(assets, "gcp-principal:user:alice@example.com")
        assert has_edge(edges, alice, sa, EdgeType.ASSUMES_ROLE, "ROLE_ASSUMES_ROLE")

    def test_merge_principals_across_collectors(self):
        sa = CloudAsset(
            arn="//iam.googleapis.com/projects/b/serviceAccounts/9",
            name="x@b.iam.gserviceaccount.com",
            asset_type=AssetType.SERVICE_PRINCIPAL,
            provider="GCP",
            metadata={"aliases": ["serviceAccount:x@b.iam.gserviceaccount.com"]},
        )
        placeholder = principal_asset("serviceAccount:x@b.iam.gserviceaccount.com")
        placeholder.metadata["relations"] = [{"target": "//storage.googleapis.com/b1", "edge": "GRANTS_ACCESS"}]
        assets, _ = merge_gcp_principals([sa, placeholder])
        assert assets == [sa]
        assert sa.metadata["relations"][0]["target"] == "//storage.googleapis.com/b1"


# ---------------------------------------------------------------------------
# Networking and compute
# ---------------------------------------------------------------------------


class TestCompute:
    def test_firewall_semantics(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        net = by_arn(assets, NETWORK["name"])
        web, db, disabled = (by_arn(assets, f["name"]) for f in (FW_WEB, FW_DB, FW_DISABLED))
        vm1, vm2 = by_arn(assets, VM_WEB["name"]), by_arn(assets, VM_DB["name"])
        assert web.metadata["ingress_rules"][0]["protocols"] == [{"protocol": "tcp", "ports": ["443"]}]
        assert web.metadata["allows_internet_ingress"] is True
        assert disabled.metadata["allows_internet_ingress"] is False
        assert has_edge(edges, web, net, EdgeType.ATTACHED_TO)
        assert has_edge(edges, vm1, web, EdgeType.ATTACHED_TO, "PROTECTED_BY_SG")
        assert has_edge(edges, vm2, db, EdgeType.ATTACHED_TO, "PROTECTED_BY_SG")
        assert not has_edge(edges, vm1, db, EdgeType.ATTACHED_TO)
        assert not has_edge(edges, vm1, disabled, EdgeType.ATTACHED_TO)
        # vm1: external IP + open 443 -> exposed; vm2: open 22 but no external IP
        assert vm1.is_internet_exposed and not vm2.is_internet_exposed
        rule_edges = [e for e in edges if e.source_id == "0.0.0.0/0" and e.target_id == vm1.id]
        assert rule_edges and rule_edges[0].edge_type == EdgeType.SECURITY_GROUP_RULE
        assert rule_edges[0].ports == [443]
        assert not any(e.source_id == "0.0.0.0/0" and e.target_id in (web.id, db.id) for e in edges)

    def test_instance_relations(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        vm1 = by_arn(assets, VM_WEB["name"])
        sa = by_arn(assets, SERVICE_ACCOUNT["name"])
        sn = by_arn(assets, SUBNET["name"])
        net = by_arn(assets, NETWORK["name"])
        disk = by_arn(assets, DISK["name"])
        key = by_arn(assets, KEY)
        assert has_edge(edges, vm1, sa, EdgeType.ASSUMES_ROLE, "RUNS_ON")
        assert has_edge(edges, sn, vm1, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        assert has_edge(edges, net, sn, EdgeType.CONTAINS, "VPC_CONTAINS_SUBNET")
        assert has_edge(edges, disk, vm1, EdgeType.ATTACHED_TO)
        assert has_edge(edges, disk, key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        assert disk.metadata["kms_keys"] == [KEY]

    def test_load_balancer_chain(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        fr, proxy, um, bs, neg, bb, armor, cert, addr = (
            by_arn(assets, r["name"]) for r in (FR, PROXY, URL_MAP, BACKEND, NEG, BACKEND_BUCKET, ARMOR, CERT, ADDRESS)
        )
        run_svc = by_arn(assets, RUN_SVC["name"])
        bucket = by_arn(assets, BUCKET_PUBLIC["name"])
        assert fr.is_internet_exposed
        assert has_edge(edges, fr, proxy, EdgeType.ROUTE)
        assert has_edge(edges, proxy, um, EdgeType.ROUTE)
        assert has_edge(edges, um, bs, EdgeType.ROUTE)
        assert has_edge(edges, um, bb, EdgeType.ROUTE)
        assert has_edge(edges, bs, neg, EdgeType.LOAD_BALANCER_TARGET)
        assert has_edge(edges, neg, run_svc, EdgeType.LOAD_BALANCER_TARGET)
        assert has_edge(edges, bb, bucket, EdgeType.LOAD_BALANCER_TARGET)
        assert has_edge(edges, armor, bs, EdgeType.PROTECTS, "PROTECTED_BY_WAF")
        assert has_edge(edges, cert, proxy, EdgeType.REFERENCES, "CERTIFICATE_SECURES")
        assert has_edge(edges, addr, fr, EdgeType.ATTACHED_TO)

    def test_gke_and_node_pool(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        gke, np, igm, ig = (by_arn(assets, r["name"]) for r in (GKE, NODE_POOL, IGM, IG))
        sn = by_arn(assets, SUBNET["name"])
        default_sa = by_arn(assets, DEFAULT_SA["name"])
        sa = by_arn(assets, SERVICE_ACCOUNT["name"])
        key = by_arn(assets, KEY)
        assert has_edge(edges, sn, gke, EdgeType.CONTAINS)
        assert has_edge(edges, gke, default_sa, EdgeType.ASSUMES_ROLE)
        assert has_edge(edges, gke, key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        assert has_edge(edges, gke, np, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE")
        assert has_edge(edges, np, sa, EdgeType.ASSUMES_ROLE)
        assert has_edge(edges, np, igm, EdgeType.MANAGES)
        assert has_edge(edges, igm, ig, EdgeType.MANAGES)
        assert gke.is_internet_exposed  # public endpoint, no authorized networks
        assert gke.metadata["workload_pool"] == "proj-a.svc.id.goog"


# ---------------------------------------------------------------------------
# Serverless, messaging, logging
# ---------------------------------------------------------------------------


class TestServerless:
    def test_cloud_run(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        run_svc = by_arn(assets, RUN_SVC["name"])
        repo = by_arn(assets, AR_REPO["name"])
        secret = by_arn(assets, SECRET["name"])
        conn = by_arn(assets, CONNECTOR["name"])
        sql = by_arn(assets, CLOUD_SQL["name"])
        net = by_arn(assets, NETWORK["name"])
        assert run_svc.asset_type == AssetType.CONTAINER_SERVICE
        assert has_edge(edges, run_svc, repo, EdgeType.USES_IMAGE)
        assert has_edge(edges, run_svc, secret, EdgeType.REFERENCES, "READS_FROM")  # number <-> id alias
        assert has_edge(edges, run_svc, conn, EdgeType.ROUTE)
        assert has_edge(edges, run_svc, sql, EdgeType.REFERENCES)
        assert has_edge(edges, conn, net, EdgeType.ATTACHED_TO)
        assert run_svc.is_internet_exposed
        # runtime SA not collected -> non-external placeholder
        run_sa = by_arn(assets, "gcp-principal:serviceAccount:run-sa@proj-a.iam.gserviceaccount.com")
        assert run_sa.asset_type == AssetType.SERVICE_PRINCIPAL
        assert has_edge(edges, run_svc, run_sa, EdgeType.ASSUMES_ROLE, "RUNS_ON")
        assert sql.is_internet_exposed and has_edge(edges, sql, net, EdgeType.ATTACHED_TO)

    def test_pubsub_push_to_cloud_run(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        topic, sub = by_arn(assets, TOPIC["name"]), by_arn(assets, SUBSCRIPTION["name"])
        run_svc = by_arn(assets, RUN_SVC["name"])
        sa = by_arn(assets, SERVICE_ACCOUNT["name"])
        assert has_edge(edges, topic, sub, EdgeType.INVOKES)
        assert has_edge(edges, sub, run_svc, EdgeType.INVOKES, "INVOKES")
        assert has_edge(edges, sub, sa, EdgeType.ASSUMES_ROLE)
        assert sub.metadata["push_endpoint_host"] == "https://api-xyz-uc.a.run.app"

    def test_logging_sinks(self, mapped):
        assets, edges = mapped["assets"], mapped["edges"]
        sink, sink_bq = by_arn(assets, SINK_GCS["name"]), by_arn(assets, SINK_BQ["name"])
        assert sink.asset_type == AssetType.LOG_SINK
        assert has_edge(edges, sink, by_arn(assets, BUCKET_LOGS["name"]), EdgeType.LOGS_TO, "LOGS_TO")
        assert has_edge(edges, sink_bq, by_arn(assets, DATASET["name"]), EdgeType.LOGS_TO)


# ---------------------------------------------------------------------------
# Organization scope and hierarchy
# ---------------------------------------------------------------------------

ORG_ANC_B = ["projects/222", "organizations/999"]
PROJECT_B = res(
    f"{CRM}projects/222",
    "cloudresourcemanager.googleapis.com/Project",
    {"projectNumber": "222", "projectId": "proj-b", "parent": {"type": "organization", "id": "999"}},
    ancestors=ORG_ANC_B,
    parent=f"{CRM}organizations/999",
)
SECRET_B = res("//secretmanager.googleapis.com/projects/222/secrets/s", "secretmanager.googleapis.com/Secret", {}, ancestors=ORG_ANC_B)
TOPIC_B = res("//pubsub.googleapis.com/projects/proj-b/topics/t", "pubsub.googleapis.com/Topic", {}, ancestors=ORG_ANC_B)
FOLDER = res(
    f"{CRM}folders/555",
    "cloudresourcemanager.googleapis.com/Folder",
    {"name": "folders/555", "displayName": "prod", "parent": "organizations/999"},
    ancestors=["folders/555", "organizations/999"],
    parent=f"{CRM}organizations/999",
)
ORG = res(
    f"{CRM}organizations/999",
    "cloudresourcemanager.googleapis.com/Organization",
    {"name": "organizations/999", "displayName": "example.com"},
    ancestors=["organizations/999"],
    parent="",
)
ORG_SINK = res(
    "//logging.googleapis.com/organizations/999/sinks/org-audit",
    "logging.googleapis.com/LogSink",
    {"destination": "storage.googleapis.com/audit-logs", "includeChildren": True},
    ancestors=["organizations/999"],
    parent=f"{CRM}organizations/999",
)
ORGPOLICY_V2 = res(
    "//orgpolicy.googleapis.com/projects/111/policies/compute.vmExternalIpAccess",
    "orgpolicy.googleapis.com/Policy",
    {"spec": {"rules": [{"denyAll": True}]}},
)


class TestOrganization:
    def test_org_scope_account_mapping(self):
        client = FakeAssetClient(resources=[ORG, FOLDER, PROJECT_ASSET, PROJECT_B, SECRET_B, TOPIC_B, ORG_SINK, TOPIC])
        collector = GCPDeepInventoryCollector(None, client=client, organization_id="organizations/999", include_iam=False)
        assets = run(collector.collect())
        assert client.requests[0][1]["parent"] == "organizations/999"
        assert by_arn(assets, SECRET_B["name"]).account_id == "proj-b"
        assert by_arn(assets, TOPIC_B["name"]).account_id == "proj-b"
        assert by_arn(assets, TOPIC["name"]).account_id == PROJECT
        assert by_arn(assets, ORG_SINK["name"]).account_id is None
        project_b = by_arn(assets, f"{CRM}projects/222")
        assert project_b.account_id == "proj-b"
        assert {"projects/222", "222", "projects/proj-b"} <= set(project_b.metadata["aliases"])
        assert "//secretmanager.googleapis.com/projects/proj-b/secrets/s" in by_arn(assets, SECRET_B["name"]).metadata["aliases"]

    def test_org_scope_project_filter(self):
        client = FakeAssetClient(resources=[ORG, PROJECT_ASSET, PROJECT_B, SECRET_B, TOPIC_B, ORG_SINK, TOPIC])
        collector = GCPDeepInventoryCollector(
            None, client=client, organization_id="999", project_filter=[PROJECT], include_iam=False
        )
        arns = {a.arn for a in run(collector.collect())}
        assert TOPIC["name"] in arns and ORG_SINK["name"] in arns
        assert SECRET_B["name"] not in arns and TOPIC_B["name"] not in arns

    def test_hierarchy_discovery(self):
        from google.cloud import asset_v1
        from google.identity.accesscontextmanager.v1 import service_perimeter_pb2

        perimeter = asset_v1.Asset(
            name="//accesscontextmanager.googleapis.com/accessPolicies/1/servicePerimeters/p1",
            asset_type="accesscontextmanager.googleapis.com/ServicePerimeter",
            service_perimeter=service_perimeter_pb2.ServicePerimeter(
                name="accessPolicies/1/servicePerimeters/p1",
                title="prod-perimeter",
                status=service_perimeter_pb2.ServicePerimeterConfig(
                    resources=[f"projects/{NUMBER}"], restricted_services=["storage.googleapis.com"]
                ),
            ),
        )
        org_policy = {
            "name": f"{CRM}projects/{NUMBER}",
            "asset_type": "cloudresourcemanager.googleapis.com/Project",
            "org_policy": [{"constraint": "constraints/iam.disableServiceAccountKeyCreation", "boolean_policy": {"enforced": True}}],
        }
        client = FakeAssetClient(
            resources=[ORG, FOLDER, PROJECT_ASSET, PROJECT_B, ORGPOLICY_V2, TOPIC],
            org_policies=[org_policy],
            access=[perimeter],
        )
        cov = CollectionCoverage(provider="gcp")
        assets = discover_gcp_hierarchy(None, "999", client=client, coverage=cov)
        assert not any(a.arn == TOPIC["name"] for a in assets)
        edges = RelationshipLinker(assets).link()
        org, folder = by_arn(assets, f"{CRM}organizations/999"), by_arn(assets, f"{CRM}folders/555")
        proj_a, proj_b = by_arn(assets, f"{CRM}projects/{NUMBER}"), by_arn(assets, f"{CRM}projects/222")
        assert org.asset_type == AssetType.ORGANIZATION and folder.asset_type == AssetType.ORG_UNIT
        assert proj_a.asset_type == AssetType.CLOUD_ACCOUNT and proj_a.account_id == PROJECT
        assert has_edge(edges, org, folder, EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT")
        assert has_edge(edges, folder, proj_a, EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT")
        assert has_edge(edges, org, proj_b, EdgeType.CONTAINS)
        pol = by_arn(assets, "//orgpolicy.googleapis.com/projects/111/policies/iam.disableServiceAccountKeyCreation")
        assert pol.asset_type == AssetType.ORG_POLICY and pol.metadata["enforced"] is True
        assert has_edge(edges, pol, proj_a, EdgeType.GOVERNS)
        v2 = by_arn(assets, ORGPOLICY_V2["name"])
        assert has_edge(edges, v2, proj_a, EdgeType.GOVERNS, "SCP_RESTRICTS")
        p1 = by_arn(assets, perimeter.name)
        assert p1.asset_type == AssetType.GUARDRAIL
        assert p1.metadata["restricted_services"] == ["storage.googleapis.com"]
        assert has_edge(edges, p1, proj_a, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS")
        assert {s.service for s in cov.services} == {"gcp_hierarchy", "gcp_org_policies", "gcp_vpc_service_controls"}


class TestMultiCollector:
    def _run(self, monkeypatch, config, client):
        import cloudg.credentials as creds
        from cloudg.collectors.multi import MultiAccountCollector

        monkeypatch.setattr(creds, "build_gcp_credentials", lambda cfg: (None, PROJECT))

        class Injected(GCPDeepInventoryCollector):
            def __init__(self, *args, **kwargs):
                kwargs["client"] = client
                super().__init__(*args, **kwargs)

        multi = MultiAccountCollector(config, collector_overrides={"gcp": Injected})
        return run(multi.collect_all())

    def test_org_scope_single_listing(self, monkeypatch):
        from cloudg.config import CloudGConfig

        config = CloudGConfig(providers=["gcp"], gcp={"organization_id": "999", "regions": ["us-central1"]})
        client = FakeAssetClient(resources=[ORG, PROJECT_ASSET, PROJECT_B, TOPIC, TOPIC_B])
        assets, _edges, coverage = self._run(monkeypatch, config, client)
        parents = [r["parent"] for k, r in client.requests if k == "list_assets"]
        assert parents == ["organizations/999"]
        assert len(coverage) == 1 and coverage[0].account_id == "organizations/999"
        full = [s for s in coverage[0].services if s.service == "gcp_full"][0]
        assert full.status == ServiceStatus.SUCCESS
        assert {a.account_id for a in assets if a.arn in (TOPIC["name"], TOPIC_B["name"])} == {PROJECT, "proj-b"}

    def test_failure_is_visible(self, monkeypatch):
        from google.api_core import exceptions as gexc

        from cloudg.config import CloudGConfig

        config = CloudGConfig(providers=["gcp"], gcp={"project_ids": [PROJECT], "regions": ["us-central1"]})
        client = FakeAssetClient(list_error=gexc.PermissionDenied("no"), search_error=gexc.PermissionDenied("no"))
        assets, _edges, coverage = self._run(monkeypatch, config, client)
        assert assets == []
        full = [s for s in coverage[0].services if s.service == "gcp_full"][0]
        assert full.status == ServiceStatus.FAILED


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------


class TestNormalisation:
    @pytest.mark.parametrize(
        "ref,service,expected",
        [
            (SL + "zones/z/instances/i", None, C + "zones/z/instances/i"),
            ("https://compute.googleapis.com/compute/beta/projects/p/global/networks/n", None, "//compute.googleapis.com/projects/p/global/networks/n"),
            ("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/7", None, "//cloudkms.googleapis.com/projects/p/locations/l/keyRings/r/cryptoKeys/k"),
            ("https://container.googleapis.com/v1/projects/p/zones/z/clusters/c", None, "//container.googleapis.com/projects/p/locations/z/clusters/c"),
            ("https://sqladmin.googleapis.com/sql/v1beta4/projects/p/instances/db", None, "//cloudsql.googleapis.com/projects/p/instances/db"),
            ("storage.googleapis.com/b1", None, "//storage.googleapis.com/b1"),
            ("pubsub.googleapis.com/projects/p/topics/t", None, "//pubsub.googleapis.com/projects/p/topics/t"),
            ("gs://b1/dags", None, "//storage.googleapis.com/b1"),
            ("projects/p/locations/l/clusters/c", "container", "//container.googleapis.com/projects/p/locations/l/clusters/c"),
            ("not a reference", None, None),
        ],
    )
    def test_full_name(self, ref, service, expected):
        assert full_name(ref, service) == expected

    def test_image_repository(self):
        assert image_repository("europe-west1-docker.pkg.dev/p/r/img:tag") == (
            "//artifactregistry.googleapis.com/projects/p/locations/europe-west1/repositories/r"
        )
        assert image_repository("eu.gcr.io/p/img") == (
            "//artifactregistry.googleapis.com/projects/p/locations/europe/repositories/eu.gcr.io"
        )
        assert image_repository("nginx:latest") is None
