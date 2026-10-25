"""Edges of the Cloud Asset Inventory extractors added for AWS depth parity.

One inventory holds a record per new extractor plus the resources its
relations point at (a stub of type ``widgets.googleapis.com/Stub`` when the
target has no record of its own). Each case asserts one linked edge with
``has_edge``.
"""

from __future__ import annotations

import base64

import pytest

from cloudg.inventory.gcp_deep import GCPDeepInventoryCollector
from cloudg.inventory.gcp_relations import EXTRACTORS, GCPContext, extract
from cloudg.inventory.gcp_relations.data_ext import sql_table_refs
from cloudg.inventory.gcp_relations.identity_ext import deny_attachment_point, v1_member
from cloudg.inventory.gcp_relations.integration import workflow_calls
from cloudg.inventory.gcp_relations.ops import filter_targets
from cloudg.inventory.catalogs import load_catalog
from cloudg.schema.models import AssetType, EdgeType
from tests.test_gcp_inventory import (
    APP_SA,
    CRM,
    NUMBER,
    PROJECT,
    PROJECT_ASSET,
    SL,
    C,
    FakeAssetClient,
    _collect,
    by_arn,
    has_edge,
    res,
)

E = EdgeType
CR = "//container.googleapis.com/projects/proj-a/locations/us-central1/clusters/gke1"
NET1 = C + "global/networks/net1"
NET2 = C + "global/networks/net2"
SUB1 = C + "regions/us-central1/subnetworks/sub1"
BKT = "//storage.googleapis.com/media-bkt"
SINK = "//storage.googleapis.com/sink-bkt"
TOPIC = "//pubsub.googleapis.com/projects/proj-a/topics/ch-topic"
SECRET = "//secretmanager.googleapis.com/projects/proj-a/secrets/cdnkey"
REPO = "//artifactregistry.googleapis.com/projects/proj-a/locations/us/repositories/repo"
RUN_URI = "https://orders-abc-uc.a.run.app"
RUN = "//run.googleapis.com/projects/proj-a/locations/us-central1/services/orders"
WF = "//workflows.googleapis.com/projects/proj-a/locations/us-central1/workflows/wf"
DS = "//bigquery.googleapis.com/projects/proj-a/datasets/ds"
BASE = DS + "/tables/base"
PROJ = f"{CRM}projects/{NUMBER}"
ORG = f"{CRM}organizations/999"
HUB = "//networkconnectivity.googleapis.com/projects/proj-a/locations/global/hubs/h"
NSEC = "//networksecurity.googleapis.com/"
NSVC = "//networkservices.googleapis.com/projects/proj-a/locations/global/"
CM = "//certificatemanager.googleapis.com/projects/proj-a/locations/global/"
POOL = "//privateca.googleapis.com/projects/proj-a/locations/us-central1/caPools/pool"
APIGEE = "//apigee.googleapis.com/organizations/proj-a"
KAFKA = "//managedkafka.googleapis.com/projects/proj-a/locations/us-central1/clusters/kc"
SPANNER = "//spanner.googleapis.com/projects/proj-a/instances/sp"
BT = "//bigtableadmin.googleapis.com/projects/proj-a/instances/bt"
AI = "//aiplatform.googleapis.com/projects/proj-a/locations/us-central1/"
DE = "//discoveryengine.googleapis.com/projects/proj-a/locations/global/collections/default_collection"
BDR = "//backupdr.googleapis.com/projects/proj-a/locations/us-central1/"
NETAPP = "//netapp.googleapis.com/projects/proj-a/locations/us-central1/"
VM = C + "zones/us-central1-a/instances/st-vm"
SCHED_POLICY = C + "regions/us-central1/resourcePolicies/sched"
SNAP_POLICY = C + "regions/us-central1/resourcePolicies/snap"
IDS = "//ids.googleapis.com/projects/proj-a/locations/us-central1-a/endpoints/ids1"
SA_ARN = f"//iam.googleapis.com/projects/{PROJECT}/serviceAccounts/{APP_SA}"


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


OPENAPI = f"""
swagger: "2.0"
info: {{title: orders, version: "1"}}
x-google-backend:
  address: {RUN_URI}
securityDefinitions:
  svc_jwt:
    type: oauth2
    flow: implicit
    authorizationUrl: ""
    x-google-issuer: "{APP_SA}"
    x-google-jwks_uri: "https://www.googleapis.com/robot/v1/metadata/x509/{APP_SA}"
    x-google-audiences: "orders-api"
paths: {{}}
"""

WORKFLOW_SOURCE = """main:
  steps:
  - publish:
      call: googleapis.pubsub.v1.projects.topics.publish
      args:
        topic: projects/proj-a/topics/ch-topic
  - read:
      call: googleapis.secretmanager.v1.projects.secrets.versions.accessString
      args:
        name: projects/proj-a/secrets/cdnkey/versions/latest
  - ping:
      call: http.get
      args:
        url: https://orders-abc-uc.a.run.app/health
"""


def R(name, asset_type, data=None, location="", ancestors=None):
    return res(name, asset_type, data or {}, location=location, ancestors=ancestors)


RESOURCES = [
    PROJECT_ASSET,
    R(
        ORG,
        "cloudresourcemanager.googleapis.com/Organization",
        {"displayName": "example.com"},
        ancestors=["organizations/999"],
    ),
    R(NET1, "compute.googleapis.com/Network", {"name": "net1"}),
    R(NET2, "compute.googleapis.com/Network", {"name": "net2"}),
    R(
        SUB1,
        "compute.googleapis.com/Subnetwork",
        {"name": "sub1", "network": SL + "global/networks/net1"},
        "us-central1",
    ),
    R(BKT, "storage.googleapis.com/Bucket", {"name": "media-bkt", "labels": {"goog-dm": "web"}}),
    R(SINK, "storage.googleapis.com/Bucket", {"name": "sink-bkt"}),
    R(TOPIC, "pubsub.googleapis.com/Topic", {}),
    R(SECRET, "secretmanager.googleapis.com/Secret", {}),
    R(REPO, "artifactregistry.googleapis.com/Repository", {"format": "DOCKER"}, "us"),
    R(RUN, "run.googleapis.com/Service", {"template": {}, "uri": RUN_URI}, "us-central1"),
    R(SA_ARN, "iam.googleapis.com/ServiceAccount", {"email": APP_SA, "projectId": PROJECT}),
    R(DS, "bigquery.googleapis.com/Dataset", {}),
    R(BASE, "bigquery.googleapis.com/Table", {"type": "TABLE"}),
    R(
        CR,
        "container.googleapis.com/Cluster",
        {"name": "gke1", "addonsConfig": {"configConnectorConfig": {"enabled": True}}},
        "us-central1",
    ),
    # --- hybrid
    R(
        HUB,
        "networkconnectivity.googleapis.com/Hub",
        {"routingVpcs": [{"uri": SL + "global/networks/net1"}]},
    ),
    R(HUB + "/routeTables/rt", "networkconnectivity.googleapis.com/RouteTable"),
    R(HUB + "/groups/g", "networkconnectivity.googleapis.com/Group"),
    R(
        "//networkconnectivity.googleapis.com/projects/proj-a/locations/global/internalRanges/ir",
        "networkconnectivity.googleapis.com/InternalRange",
        {"network": "net1"},
    ),
    R(
        "//networkconnectivity.googleapis.com/projects/proj-a/locations/global/policyBasedRoutes/pbr",
        "networkconnectivity.googleapis.com/PolicyBasedRoute",
        {"network": SL + "global/networks/net1", "nextHopIlbIp": "10.0.0.9"},
    ),
    R(
        C + "regions/us-central1/addresses/ilb",
        "compute.googleapis.com/Address",
        {"address": "10.0.0.9", "addressType": "EXTERNAL"},
        "us-central1",
    ),
    R(
        "//networkconnectivity.googleapis.com/projects/proj-a/locations/us-central1/regionalEndpoints/re",
        "networkconnectivity.googleapis.com/RegionalEndpoint",
        {"network": "net1"},
    ),
    R(
        C + "global/interconnects/ic",
        "compute.googleapis.com/Interconnect",
        {"interconnectAttachments": [SL + "regions/us-central1/interconnectAttachments/att"]},
    ),
    R(
        C + "regions/us-central1/interconnectAttachments/att",
        "compute.googleapis.com/InterconnectAttachment",
        {},
        "us-central1",
    ),
    R(
        C + "global/externalVpnGateways/evg",
        "compute.googleapis.com/ExternalVpnGateway",
        {"interfaces": [{"ipAddress": "203.0.113.5"}]},
    ),
    R(
        C + "regions/us-central1/vpnTunnels/t1",
        "compute.googleapis.com/VpnTunnel",
        {"peerIp": "203.0.113.5"},
        "us-central1",
    ),
    R(
        C + "regions/us-central1/serviceAttachments/sa1",
        "compute.googleapis.com/ServiceAttachment",
        {"consumerAcceptLists": [{"projectIdOrNum": "proj-c", "connectionLimit": 5}]},
        "us-central1",
    ),
    R(
        C + "regions/us-central1/packetMirrorings/pm",
        "compute.googleapis.com/PacketMirroring",
        {
            "collectorIlb": {"url": SL + "regions/us-central1/forwardingRules/ids-fr"},
            "mirroredResources": {
                "subnetworks": [{"url": SL + "regions/us-central1/subnetworks/sub1"}]
            },
        },
        "us-central1",
    ),
    R(
        C + "regions/us-central1/nodeTemplates/nt",
        "compute.googleapis.com/NodeTemplate",
        {"nodeType": "n1-node-96-624"},
        "us-central1",
    ),
    R(
        C + "zones/us-central1-a/nodeGroups/ng",
        "compute.googleapis.com/NodeGroup",
        {"nodeTemplate": SL + "regions/us-central1/nodeTemplates/nt", "size": 2},
        "us-central1-a",
    ),
    R(
        VM,
        "compute.googleapis.com/Instance",
        {
            "name": "st-vm",
            "id": "4242",
            "labels": {"env": "prod"},
            "scheduling": {
                "nodeAffinities": [
                    {
                        "key": "compute.googleapis.com/node-group-name",
                        "operator": "IN",
                        "values": ["ng"],
                    }
                ]
            },
            "resourcePolicies": [SL + "regions/us-central1/resourcePolicies/sched"],
        },
        "us-central1-a",
    ),
    R(
        SCHED_POLICY,
        "compute.googleapis.com/ResourcePolicy",
        {
            "instanceSchedulePolicy": {
                "vmStartSchedule": {"schedule": "0 8 * * *"},
                "timeZone": "UTC",
            }
        },
        "us-central1",
    ),
    R(
        SNAP_POLICY,
        "compute.googleapis.com/ResourcePolicy",
        {
            "snapshotSchedulePolicy": {
                "schedule": {"dailySchedule": {}},
                "retentionPolicy": {"maxRetentionDays": 14},
            }
        },
        "us-central1",
    ),
    R(
        C + "zones/us-central1-a/disks/d1",
        "compute.googleapis.com/Disk",
        {"resourcePolicies": [SL + "regions/us-central1/resourcePolicies/snap"]},
        "us-central1-a",
    ),
    # --- network security and services
    R(
        NSEC + "organizations/999/locations/us-central1-a/firewallEndpoints/fe",
        "networksecurity.googleapis.com/FirewallEndpoint",
        {"associatedNetworks": [SL + "global/networks/net1"]},
    ),
    R(
        NSEC + "projects/proj-a/locations/us-central1-a/firewallEndpointAssociations/a",
        "networksecurity.googleapis.com/FirewallEndpointAssociation",
        {
            "network": SL + "global/networks/net2",
            "firewallEndpoint": "organizations/999/locations/us-central1-a/firewallEndpoints/fe",
        },
    ),
    R(
        NSEC + "organizations/999/locations/global/securityProfiles/sp",
        "networksecurity.googleapis.com/SecurityProfile",
        {"type": "THREAT_PREVENTION"},
    ),
    R(
        NSEC + "organizations/999/locations/global/securityProfileGroups/spg",
        "networksecurity.googleapis.com/SecurityProfileGroup",
        {"threatPreventionProfile": "organizations/999/locations/global/securityProfiles/sp"},
    ),
    R(
        NSEC + "projects/proj-a/locations/us-central1/tlsInspectionPolicies/tip",
        "networksecurity.googleapis.com/TlsInspectionPolicy",
        {"caPool": "projects/proj-a/locations/us-central1/caPools/pool"},
    ),
    R(POOL, "privateca.googleapis.com/CaPool", {"tier": "ENTERPRISE"}, "us-central1"),
    R(
        NSEC + "projects/proj-a/locations/global/serverTlsPolicies/stp",
        "networksecurity.googleapis.com/ServerTlsPolicy",
        {
            "mtlsPolicy": {
                "clientValidationTrustConfig": "projects/proj-a/locations/global/trustConfigs/tc"
            }
        },
    ),
    R(
        CM + "trustConfigs/tc",
        "certificatemanager.googleapis.com/TrustConfig",
        {"trustStores": [{}]},
    ),
    R(
        NSEC + "projects/proj-a/locations/global/authzPolicies/az",
        "networksecurity.googleapis.com/AuthzPolicy",
        {"target": {"resources": [SL + "global/forwardingRules/fr1"]}, "action": "DENY"},
    ),
    R(
        NSEC + "projects/proj-a/locations/global/addressGroups/ag",
        "networksecurity.googleapis.com/AddressGroup",
        {"items": ["10.0.0.0/8"], "capacity": 100},
    ),
    R(
        C + "global/firewallPolicies/fwp",
        "compute.googleapis.com/NetworkFirewallPolicy",
        {
            "rules": [
                {
                    "priority": 1,
                    "securityProfileGroup": "//networksecurity.googleapis.com/organizations/999/locations/global/securityProfileGroups/spg",
                }
            ]
        },
    ),
    R(
        IDS,
        "ids.googleapis.com/Endpoint",
        {
            "network": SL + "global/networks/net1",
            "endpointForwardingRule": SL + "regions/us-central1/forwardingRules/ids-fr",
            "severity": "INFORMATIONAL",
        },
        "us-central1-a",
    ),
    R(
        NSVC + "gateways/swp",
        "networkservices.googleapis.com/Gateway",
        {
            "type": "SECURE_WEB_GATEWAY",
            "network": "net1",
            "certificateUrls": ["projects/proj-a/locations/global/certificates/c1"],
        },
    ),
    R(NSVC + "meshes/mesh", "networkservices.googleapis.com/Mesh", {"interceptionPort": 15001}),
    R(
        NSVC + "httpRoutes/hr",
        "networkservices.googleapis.com/HttpRoute",
        {
            "gateways": [NSVC + "gateways/swp"],
            "rules": [
                {
                    "action": {
                        "destinations": [
                            {"serviceName": "projects/proj-a/locations/global/backendServices/bs1"}
                        ]
                    }
                }
            ],
        },
    ),
    R(C + "global/backendServices/bs1", "compute.googleapis.com/BackendService", {}),
    R(
        NSVC + "serviceBindings/sb",
        "networkservices.googleapis.com/ServiceBinding",
        {"service": "projects/proj-a/locations/us-central1/namespaces/ns/services/svc"},
    ),
    R(
        NSVC + "endpointPolicies/ep",
        "networkservices.googleapis.com/EndpointPolicy",
        {"serverTlsPolicy": "projects/proj-a/locations/global/serverTlsPolicies/stp"},
    ),
    R(
        NSVC + "edgeCacheServices/cdn",
        "networkservices.googleapis.com/EdgeCacheService",
        {
            "routing": {
                "hostRules": [{"hosts": ["cdn.example.com"]}],
                "pathMatchers": [
                    {
                        "routeRules": [
                            {"origin": "projects/proj-a/locations/global/edgeCacheOrigins/o1"}
                        ]
                    }
                ],
            },
            "edgeSecurityPolicy": SL + "global/securityPolicies/armor",
        },
    ),
    R(
        NSVC + "edgeCacheOrigins/o1",
        "networkservices.googleapis.com/EdgeCacheOrigin",
        {"originAddress": "gs://media-bkt"},
    ),
    R(C + "global/securityPolicies/armor", "compute.googleapis.com/SecurityPolicy", {}),
    R(
        NSVC + "edgeCacheKeysets/ks",
        "networkservices.googleapis.com/EdgeCacheKeyset",
        {"validationSharedKeys": [{"secretVersion": "projects/proj-a/secrets/cdnkey/versions/1"}]},
    ),
    R(
        NSVC + "serviceLbPolicies/lbp",
        "networkservices.googleapis.com/ServiceLbPolicy",
        {"loadBalancingAlgorithm": "WATERFALL_BY_REGION"},
    ),
    R(
        C + "regions/us-central1/networkEdgeSecurityServices/ness",
        "compute.googleapis.com/NetworkEdgeSecurityService",
        {"securityPolicy": SL + "global/securityPolicies/armor"},
        "us-central1",
    ),
    # --- edge
    R(
        CM + "certificates/c1",
        "certificatemanager.googleapis.com/Certificate",
        {
            "managed": {
                "domains": ["api.example.com"],
                "dnsAuthorizations": ["projects/proj-a/locations/global/dnsAuthorizations/da"],
            }
        },
    ),
    R(
        CM + "dnsAuthorizations/da",
        "certificatemanager.googleapis.com/DnsAuthorization",
        {"domain": "api.example.com"},
    ),
    R(
        CM + "certificateMaps/map",
        "certificatemanager.googleapis.com/CertificateMap",
        {"gclbTargets": [{"targetHttpsProxy": SL + "global/targetHttpsProxies/px"}]},
    ),
    R(C + "global/targetHttpsProxies/px", "compute.googleapis.com/TargetHttpsProxy", {}),
    R(
        CM + "certificateMaps/map/certificateMapEntries/e",
        "certificatemanager.googleapis.com/CertificateMapEntry",
        {
            "certificates": ["projects/proj-a/locations/global/certificates/c1"],
            "hostname": "api.example.com",
        },
    ),
    R(
        CM + "certificateIssuanceConfigs/ic",
        "certificatemanager.googleapis.com/CertificateIssuanceConfig",
        {
            "certificateAuthorityConfig": {
                "certificateAuthorityServiceConfig": {
                    "caPool": "projects/proj-a/locations/us-central1/caPools/pool"
                }
            }
        },
    ),
    R(
        POOL + "/certificateAuthorities/ca1",
        "privateca.googleapis.com/CertificateAuthority",
        {"gcsBucket": "media-bkt", "type": "SELF_SIGNED"},
        "us-central1",
    ),
    R(
        "//run.googleapis.com/projects/proj-a/locations/us-central1/domainmappings/api.example.com",
        "run.googleapis.com/DomainMapping",
        {"metadata": {"name": "api.example.com"}, "spec": {"routeName": "orders"}},
        "us-central1",
    ),
    R(
        "//identitytoolkit.googleapis.com/projects/proj-a/config",
        "identitytoolkit.googleapis.com/Config",
        {
            "blockingFunctions": {
                "triggers": {
                    "beforeCreate": {
                        "functionUri": "https://us-central1-proj-a.cloudfunctions.net/block"
                    }
                }
            },
            "signIn": {"email": {"enabled": True}},
        },
    ),
    R(
        "//cloudfunctions.googleapis.com/projects/proj-a/locations/us-central1/functions/block",
        "cloudfunctions.googleapis.com/CloudFunction",
        {
            "httpsTrigger": {"url": "https://us-central1-proj-a.cloudfunctions.net/block"},
            "serviceAccountEmail": APP_SA,
        },
        "us-central1",
    ),
    R(
        "//identitytoolkit.googleapis.com/projects/proj-a/tenants/t1",
        "identitytoolkit.googleapis.com/Tenant",
        {"allowPasswordSignup": True},
    ),
    R(
        "//identitytoolkit.googleapis.com/projects/proj-a/oauthIdpConfigs/oidc.corp",
        "identitytoolkit.googleapis.com/OauthIdpConfig",
        {"enabled": True, "issuer": "https://corp.example.com"},
    ),
    # --- APIs
    R(
        APIGEE,
        "apigee.googleapis.com/Organization",
        {"projectId": PROJECT, "authorizedNetwork": "net1", "runtimeType": "CLOUD"},
    ),
    R(
        APIGEE + "/instances/i1",
        "apigee.googleapis.com/Instance",
        {
            "serviceAttachment": SL + "regions/us-central1/serviceAttachments/sa1",
            "host": "10.1.0.2",
        },
        "us-central1",
    ),
    R(
        APIGEE + "/environments/prod",
        "apigee.googleapis.com/Environment",
        {"deploymentType": "PROXY"},
    ),
    R(APIGEE + "/apis/orders", "apigee.googleapis.com/ApiProxy", {"latestRevisionId": "1"}),
    R(
        APIGEE + "/apis/orders/revisions/1",
        "apigee.googleapis.com/ApiProxyRevision",
        {"targetServers": ["ts"]},
    ),
    R(
        "//apigateway.googleapis.com/projects/proj-a/locations/global/apis/orders/configs/v1",
        "apigateway.googleapis.com/ApiConfig",
        {"openapiDocuments": [{"document": {"path": "openapi.yaml", "contents": b64(OPENAPI)}}]},
    ),
    # --- containers
    R(
        REPO + "/dockerImages/img@sha256:abc",
        "artifactregistry.googleapis.com/DockerImage",
        {
            "uri": "us-docker.pkg.dev/proj-a/repo/img@sha256:abc",
            "tags": ["1"],
            "uploadTime": "2026-10-01T00:00:00Z",
        },
        "us",
    ),
    R(
        REPO + "-virtual",
        "artifactregistry.googleapis.com/Repository",
        {
            "mode": "VIRTUAL_REPOSITORY",
            "virtualRepositoryConfig": {
                "upstreamPolicies": [
                    {"repository": "projects/proj-a/locations/us/repositories/repo", "priority": 1}
                ]
            },
        },
        "us",
    ),
    R(
        "//binaryauthorization.googleapis.com/projects/proj-a/policy",
        "binaryauthorization.googleapis.com/Policy",
        {
            "clusterAdmissionRules": {
                "us-central1.gke1": {
                    "evaluationMode": "REQUIRE_ATTESTATION",
                    "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG",
                    "requireAttestationsBy": ["projects/proj-a/attestors/att"],
                }
            },
            "defaultAdmissionRule": {"evaluationMode": "ALWAYS_ALLOW"},
        },
    ),
    R(
        "//binaryauthorization.googleapis.com/projects/proj-a/attestors/att",
        "binaryauthorization.googleapis.com/Attestor",
        {
            "userOwnedGrafeasNote": {
                "noteReference": "projects/proj-a/notes/n",
                "delegationServiceAccountEmail": "attestor@proj-a.iam.gserviceaccount.com",
            }
        },
    ),
    R(
        "//binaryauthorization.googleapis.com/projects/proj-a/platforms/gke/policies/pp",
        "binaryauthorization.googleapis.com/PlatformPolicy",
        {"gkePolicy": {"checkSets": [{}]}},
    ),
    R(
        "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1",
        "gkehub.googleapis.com/Membership",
        {"endpoint": {"gkeCluster": {"resourceLink": CR}}},
    ),
    R(
        "//gkehub.googleapis.com/projects/proj-a/locations/global/features/configmanagement",
        "gkehub.googleapis.com/Feature",
        {"membershipSpecs": {"projects/111/locations/global/memberships/m1": {}}},
    ),
    R(
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team",
        "gkehub.googleapis.com/Scope",
        {},
    ),
    R(
        "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1/bindings/b1",
        "gkehub.googleapis.com/MembershipBinding",
        {"scope": "projects/proj-a/locations/global/scopes/team"},
    ),
    R(
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team/namespaces/ns1",
        "gkehub.googleapis.com/Namespace",
        {},
    ),
    R(
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team/rbacrolebindings/rb",
        "gkehub.googleapis.com/RBACRoleBinding",
        {"user": "alice@example.com", "role": {"predefinedRole": "ADMIN"}},
    ),
    R(
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/backupPlans/bp",
        "gkebackup.googleapis.com/BackupPlan",
        {
            "cluster": "projects/proj-a/locations/us-central1/clusters/gke1",
            "backupSchedule": {"cronSchedule": "0 3 * * *"},
        },
        "us-central1",
    ),
    R(
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/backupPlans/bp/backups/b",
        "gkebackup.googleapis.com/Backup",
        {"state": "SUCCEEDED"},
        "us-central1",
    ),
    R(
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/restorePlans/rp",
        "gkebackup.googleapis.com/RestorePlan",
        {
            "cluster": "projects/proj-a/locations/us-central1/clusters/gke1",
            "backupPlan": "projects/proj-a/locations/us-central1/backupPlans/bp",
        },
        "us-central1",
    ),
    R(
        CR + "/k8s/namespaces/team",
        "k8s.io/Namespace",
        {"status": {"phase": "Active"}},
        "us-central1",
    ),
    R(
        CR + "/k8s/clusterroles/admin",
        "rbac.authorization.k8s.io/ClusterRole",
        {"rules": [{"verbs": ["*"], "resources": ["secrets"]}]},
        "us-central1",
    ),
    # --- integration
    R(
        "//cloudscheduler.googleapis.com/projects/proj-a/locations/us-central1/jobs/nightly",
        "cloudscheduler.googleapis.com/Job",
        {
            "schedule": "0 2 * * *",
            "httpTarget": {
                "uri": "https://workflowexecutions.googleapis.com/v1/projects/proj-a/locations/us-central1/workflows/wf/executions",
                "oidcToken": {"serviceAccountEmail": APP_SA},
            },
        },
        "us-central1",
    ),
    R(
        WF,
        "workflows.googleapis.com/Workflow",
        {
            "serviceAccount": f"projects/{PROJECT}/serviceAccounts/{APP_SA}",
            "sourceContents": WORKFLOW_SOURCE,
        },
        "us-central1",
    ),
    R(
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/channels/ch",
        "eventarc.googleapis.com/Channel",
        {
            "pubsubTopic": "projects/proj-a/topics/ch-topic",
            "activationToken": "tok-secret",
            "provider": "saas",
        },
        "us-central1",
    ),
    R(
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/channelConnections/cc",
        "eventarc.googleapis.com/ChannelConnection",
        {"channel": "projects/proj-a/locations/us-central1/channels/ch"},
        "us-central1",
    ),
    R(
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/triggers/tr",
        "eventarc.googleapis.com/Trigger",
        {"channel": "projects/proj-a/locations/us-central1/channels/ch", "destination": {}},
        "us-central1",
    ),
    R(
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/messageBuses/bus",
        "eventarc.googleapis.com/MessageBus",
        {},
        "us-central1",
    ),
    R(
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/googleApiSources/src",
        "eventarc.googleapis.com/GoogleApiSource",
        {"destination": "projects/proj-a/locations/us-central1/messageBuses/bus"},
        "us-central1",
    ),
    R(
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/enrollments/en",
        "eventarc.googleapis.com/Enrollment",
        {
            "messageBus": "projects/proj-a/locations/us-central1/messageBuses/bus",
            "destination": "projects/proj-a/locations/us-central1/pipelines/pl",
            "celMatch": "true",
        },
        "us-central1",
    ),
    R(
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/pipelines/pl",
        "eventarc.googleapis.com/Pipeline",
        {"destinations": [{"workflow": "projects/proj-a/locations/us-central1/workflows/wf"}]},
        "us-central1",
    ),
    R(KAFKA, "managedkafka.googleapis.com/Cluster", {}, "us-central1"),
    R(
        KAFKA + "/topics/orders",
        "managedkafka.googleapis.com/Topic",
        {"partitionCount": 3},
        "us-central1",
    ),
    R(
        KAFKA + "/consumerGroups/cg",
        "managedkafka.googleapis.com/ConsumerGroup",
        {"topics": {"orders": {}}},
        "us-central1",
    ),
    R(
        "//managedkafka.googleapis.com/projects/proj-a/locations/us-central1/connectClusters/cc",
        "managedkafka.googleapis.com/ConnectCluster",
        {"kafkaCluster": "projects/proj-a/locations/us-central1/clusters/kc"},
        "us-central1",
    ),
    R(
        "//managedkafka.googleapis.com/projects/proj-a/locations/us-central1/connectClusters/cc/connectors/sink",
        "managedkafka.googleapis.com/Connector",
        {
            "configs": {
                "connector.class": "com.google.pubsub.kafka.sink.CloudPubSubSinkConnector",
                "cps.topic": "ch-topic",
                "cps.project": "proj-a",
            }
        },
        "us-central1",
    ),
    R(
        "//pubsub.googleapis.com/projects/proj-a/snapshots/snap",
        "pubsub.googleapis.com/Snapshot",
        {"topic": "projects/proj-a/topics/ch-topic"},
    ),
    R(
        "//pubsub.googleapis.com/projects/proj-a/schemas/orders",
        "pubsub.googleapis.com/Schema",
        {"type": "AVRO"},
    ),
    R(
        "//batch.googleapis.com/projects/proj-a/locations/us-central1/jobs/b1",
        "batch.googleapis.com/Job",
        {
            "allocationPolicy": {
                "serviceAccount": {"email": APP_SA},
                "network": {
                    "networkInterfaces": [
                        {"subnetwork": SL + "regions/us-central1/subnetworks/sub1"}
                    ]
                },
            },
            "taskGroups": [
                {
                    "taskSpec": {
                        "runnables": [
                            {"container": {"imageUri": "us-docker.pkg.dev/proj-a/repo/img:1"}}
                        ],
                        "volumes": [{"gcs": {"remotePath": "media-bkt/in"}}],
                    }
                }
            ],
        },
        "us-central1",
    ),
    # --- data
    R(
        SPANNER,
        "spanner.googleapis.com/Instance",
        {"config": "projects/proj-a/instanceConfigs/regional-us-central1", "nodeCount": 1},
    ),
    R(
        SPANNER + "/databases/db",
        "spanner.googleapis.com/Database",
        {"databaseDialect": "GOOGLE_STANDARD_SQL"},
    ),
    R(
        SPANNER + "/backups/bk",
        "spanner.googleapis.com/Backup",
        {"database": "projects/proj-a/instances/sp/databases/db"},
    ),
    R(BT, "bigtableadmin.googleapis.com/Instance", {"type": "PRODUCTION"}),
    R(
        BT + "/clusters/c1",
        "bigtableadmin.googleapis.com/Cluster",
        {"serveNodes": 3},
        "us-central1-b",
    ),
    R(BT + "/tables/t1", "bigtableadmin.googleapis.com/Table", {"deletionProtection": True}),
    R(BT + "/tables/t1/authorizedViews/v", "bigtableadmin.googleapis.com/AuthorizedView", {}),
    R(
        BT + "/clusters/c1/backups/b1",
        "bigtableadmin.googleapis.com/Backup",
        {"sourceTable": "projects/proj-a/instances/bt/tables/t1"},
    ),
    R(
        BT + "/appProfiles/ap",
        "bigtableadmin.googleapis.com/AppProfile",
        {"singleClusterRouting": {"clusterId": "c1"}},
    ),
    R(
        "//firestore.googleapis.com/projects/proj-a/databases/(default)",
        "firestore.googleapis.com/Database",
        {
            "type": "FIRESTORE_NATIVE",
            "pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_ENABLED",
        },
        "nam5",
    ),
    R(
        "//firestore.googleapis.com/projects/proj-a/locations/nam5/backups/fb",
        "firestore.googleapis.com/Backup",
        {"database": "projects/proj-a/databases/(default)"},
        "nam5",
    ),
    R(
        DS + "/tables/v1",
        "bigquery.googleapis.com/Table",
        {"type": "VIEW", "view": {"query": "SELECT * FROM `proj-a.ds.base`"}},
    ),
    R(
        DS + "/routines/r",
        "bigquery.googleapis.com/Routine",
        {
            "definitionBody": "SELECT * FROM `proj-a.ds.base`",
            "routineType": "TABLE_VALUED_FUNCTION",
        },
    ),
    R(DS + "/models/m", "bigquery.googleapis.com/Model", {"modelType": "LINEAR_REG"}),
    R(
        BASE + "/rowAccessPolicies/rap",
        "bigquery.googleapis.com/RowAccessPolicy",
        {"filterPredicate": "region = 'EU'"},
    ),
    R(
        "//bigqueryconnection.googleapis.com/projects/proj-a/locations/us/connections/sqlconn",
        "bigqueryconnection.googleapis.com/Connection",
        {"cloudSql": {"instanceId": "proj-a:us-central1:db1", "database": "orders"}},
        "us",
    ),
    R(
        "//cloudsql.googleapis.com/projects/proj-a/instances/db1",
        "sqladmin.googleapis.com/Instance",
        {"databaseVersion": "POSTGRES_15"},
        "us-central1",
    ),
    R(
        "//bigquerydatatransfer.googleapis.com/projects/111/locations/us/transferConfigs/tc",
        "bigquerydatatransfer.googleapis.com/TransferConfig",
        {
            "destinationDatasetId": "ds",
            "dataSourceId": "google_cloud_storage",
            "params": {"data_path_template": "gs://media-bkt/*.csv"},
        },
        "us",
    ),
    R(
        "//metastore.googleapis.com/projects/proj-a/locations/us-central1/services/ms",
        "metastore.googleapis.com/Service",
        {"network": SL + "global/networks/net1"},
        "us-central1",
    ),
    R(
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake",
        "dataplex.googleapis.com/Lake",
        {"metastore": {"service": "projects/proj-a/locations/us-central1/services/ms"}},
        "us-central1",
    ),
    R(
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake/zones/raw",
        "dataplex.googleapis.com/Zone",
        {"type": "RAW"},
        "us-central1",
    ),
    R(
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake/zones/raw/assets/a",
        "dataplex.googleapis.com/Asset",
        {"resourceSpec": {"name": "projects/proj-a/buckets/media-bkt", "type": "STORAGE_BUCKET"}},
        "us-central1",
    ),
    R(
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake/tasks/t",
        "dataplex.googleapis.com/Task",
        {
            "executionSpec": {"serviceAccount": APP_SA},
            "spark": {"pythonScriptFile": "gs://media-bkt/job.py"},
        },
        "us-central1",
    ),
    R(
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/dataScans/dq",
        "dataplex.googleapis.com/DataScan",
        {"type": "DATA_QUALITY", "data": {"resource": BASE}},
        "us-central1",
    ),
    R(
        "//datacatalog.googleapis.com/projects/proj-a/locations/us/taxonomies/tx",
        "datacatalog.googleapis.com/Taxonomy",
        {"activatedPolicyTypes": ["FINE_GRAINED_ACCESS_CONTROL"]},
        "us",
    ),
    R(
        "//datafusion.googleapis.com/projects/proj-a/locations/us-central1/instances/df",
        "datafusion.googleapis.com/Instance",
        {
            "networkConfig": {"network": "net1"},
            "privateInstance": False,
            "dataprocServiceAccount": APP_SA,
        },
        "us-central1",
    ),
    R(
        "//datafusion.googleapis.com/projects/proj-a/locations/us-central1/instances/df/dnsPeerings/p",
        "datafusion.googleapis.com/DnsPeering",
        {"targetNetwork": "net1", "targetProject": PROJECT},
        "us-central1",
    ),
    R(
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/streams/s",
        "datastream.googleapis.com/Stream",
        {
            "sourceConfig": {
                "sourceConnectionProfile": "projects/proj-a/locations/us-central1/connectionProfiles/src"
            },
            "destinationConfig": {
                "destinationConnectionProfile": "projects/proj-a/locations/us-central1/connectionProfiles/dst"
            },
        },
        "us-central1",
    ),
    R(
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/connectionProfiles/src",
        "datastream.googleapis.com/ConnectionProfile",
        {"mysqlProfile": {"hostname": "10.0.0.9", "port": 3306, "password": "hunter2"}},
        "us-central1",
    ),
    R(
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/connectionProfiles/dst",
        "datastream.googleapis.com/ConnectionProfile",
        {"gcsProfile": {"bucket": "media-bkt"}},
        "us-central1",
    ),
    R(
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/privateConnections/pc",
        "datastream.googleapis.com/PrivateConnection",
        {"vpcPeeringConfig": {"vpc": SL + "global/networks/net1", "subnet": "10.9.0.0/29"}},
        "us-central1",
    ),
    R(
        "//storagetransfer.googleapis.com/transferJobs/123",
        "storagetransfer.googleapis.com/TransferJob",
        {
            "projectId": PROJECT,
            "transferSpec": {
                "gcsDataSource": {"bucketName": "media-bkt"},
                "gcsDataSink": {"bucketName": "sink-bkt"},
            },
        },
    ),
    R(
        NETAPP + "storagePools/pool",
        "netapp.googleapis.com/StoragePool",
        {"network": "net1", "serviceLevel": "PREMIUM"},
        "us-central1",
    ),
    R(
        NETAPP + "volumes/vol",
        "netapp.googleapis.com/Volume",
        {
            "storagePool": "projects/proj-a/locations/us-central1/storagePools/pool",
            "backupConfig": {
                "backupVault": "projects/proj-a/locations/us-central1/backupVaults/nv"
            },
        },
        "us-central1",
    ),
    R(NETAPP + "backupVaults/nv", "netapp.googleapis.com/BackupVault", {}, "us-central1"),
    R(
        NETAPP + "volumes/vol/replications/r",
        "netapp.googleapis.com/Replication",
        {"destinationVolume": "projects/proj-a/locations/us-east1/volumes/dr"},
        "us-central1",
    ),
    R(
        NETAPP + "backupVaults/nv/backups/b",
        "netapp.googleapis.com/Backup",
        {"sourceVolume": "projects/proj-a/locations/us-central1/volumes/vol"},
        "us-central1",
    ),
    R(NETAPP + "volumes/vol/snapshots/s", "netapp.googleapis.com/Snapshot", {}, "us-central1"),
    R(
        "//file.googleapis.com/projects/proj-a/locations/us-central1/backups/fsb",
        "file.googleapis.com/Backup",
        {"sourceInstance": "projects/proj-a/locations/us-central1-a/instances/fs"},
        "us-central1",
    ),
    R(
        "//file.googleapis.com/projects/proj-a/locations/us-central1-a/instances/fs",
        "file.googleapis.com/Instance",
        {},
        "us-central1-a",
    ),
    R(
        "//secretmanager.googleapis.com/projects/proj-a/secrets/rotating",
        "secretmanager.googleapis.com/Secret",
        {
            "rotation": {"rotationPeriod": "2592000s", "nextRotationTime": "2026-11-01T00:00:00Z"},
            "topics": [{"name": "projects/proj-a/topics/rot"}],
        },
    ),
    R("//pubsub.googleapis.com/projects/proj-a/topics/rot", "pubsub.googleapis.com/Topic", {}),
    R(
        "//cloudfunctions.googleapis.com/projects/proj-a/locations/us-central1/functions/rotator",
        "cloudfunctions.googleapis.com/Function",
        {
            "eventTrigger": {"pubsubTopic": "projects/proj-a/topics/rot"},
            "serviceConfig": {"serviceAccountEmail": APP_SA},
        },
        "us-central1",
    ),
    R(
        "//parametermanager.googleapis.com/projects/proj-a/locations/global/parameters/cfg",
        "parametermanager.googleapis.com/Parameter",
        {"format": "YAML"},
    ),
    R(
        "//parametermanager.googleapis.com/projects/proj-a/locations/global/parameters/cfg/versions/v1",
        "parametermanager.googleapis.com/ParameterVersion",
        {},
    ),
    R(
        "//cloudkms.googleapis.com/projects/proj-a/locations/us/keyRings/ring",
        "cloudkms.googleapis.com/KeyRing",
        {},
        "us",
    ),
    # --- ML
    R(
        AI + "reasoningEngines/agent",
        "aiplatform.googleapis.com/ReasoningEngine",
        {
            "spec": {
                "packageSpec": {"pickleObjectGcsUri": "gs://media-bkt/agent.pkl"},
                "serviceAccount": APP_SA,
                "deploymentSpec": {
                    "secretEnv": [{"name": "KEY", "secretRef": {"secret": "cdnkey"}}]
                },
            }
        },
        "us-central1",
    ),
    R(
        AI + "indexes/idx",
        "aiplatform.googleapis.com/Index",
        {"metadata": {"contentsDeltaUri": "gs://media-bkt/emb"}},
        "us-central1",
    ),
    R(
        AI + "indexEndpoints/ie",
        "aiplatform.googleapis.com/IndexEndpoint",
        {
            "deployedIndexes": [
                {"id": "d1", "index": "projects/proj-a/locations/us-central1/indexes/idx"}
            ],
            "publicEndpointEnabled": True,
        },
        "us-central1",
    ),
    R(
        DE + "/dataStores/kb",
        "discoveryengine.googleapis.com/DataStore",
        {"industryVertical": "GENERIC"},
    ),
    R(DE, "discoveryengine.googleapis.com/Collection", {}),
    R(
        DE + "/engines/e",
        "discoveryengine.googleapis.com/Engine",
        {"dataStoreIds": ["kb"], "solutionType": "SOLUTION_TYPE_SEARCH"},
    ),
    R(DE + "/engines/e/assistants/a", "discoveryengine.googleapis.com/Assistant", {}),
    R(
        "//dialogflow.googleapis.com/projects/proj-a/locations/global/agents/bot",
        "dialogflow.googleapis.com/Agent",
        {"securitySettings": "projects/proj-a/locations/global/securitySettings/ss"},
    ),
    R(
        "//dialogflow.googleapis.com/projects/proj-a/knowledgeBases/kbase",
        "dialogflow.googleapis.com/KnowledgeBase",
        {"languageCode": "en"},
    ),
    R(
        "//modelarmor.googleapis.com/projects/proj-a/locations/us-central1/templates/guard",
        "modelarmor.googleapis.com/Template",
        {"filterConfig": {"piAndJailbreakFilterSettings": {}}},
        "us-central1",
    ),
    R(
        AI + "customJobs/cj",
        "aiplatform.googleapis.com/CustomJob",
        {
            "jobSpec": {
                "serviceAccount": APP_SA,
                "workerPoolSpecs": [
                    {"containerSpec": {"imageUri": "us-docker.pkg.dev/proj-a/repo/train:1"}}
                ],
                "baseOutputDirectory": {"outputUriPrefix": "gs://sink-bkt/out"},
            }
        },
        "us-central1",
    ),
    R(
        AI + "hyperparameterTuningJobs/hp",
        "aiplatform.googleapis.com/HyperparameterTuningJob",
        {
            "trialJobSpec": {
                "workerPoolSpecs": [
                    {"containerSpec": {"imageUri": "us-docker.pkg.dev/proj-a/repo/train:1"}}
                ]
            }
        },
        "us-central1",
    ),
    R(
        AI + "datasets/777",
        "aiplatform.googleapis.com/Dataset",
        {"metadata": {"inputConfig": {"gcsSource": {"uri": ["gs://media-bkt/data.csv"]}}}},
        "us-central1",
    ),
    R(
        AI + "trainingPipelines/tp",
        "aiplatform.googleapis.com/TrainingPipeline",
        {"inputDataConfig": {"datasetId": "777"}},
        "us-central1",
    ),
    R(
        AI + "pipelineJobs/pj",
        "aiplatform.googleapis.com/PipelineJob",
        {"serviceAccount": APP_SA, "runtimeConfig": {"gcsOutputDirectory": "gs://sink-bkt/root"}},
        "us-central1",
    ),
    R(
        AI + "batchPredictionJobs/bp",
        "aiplatform.googleapis.com/BatchPredictionJob",
        {
            "inputConfig": {"bigquerySource": {"inputUri": "bq://proj-a.ds.base"}},
            "outputConfig": {"gcsDestination": {"outputUriPrefix": "gs://sink-bkt/pred"}},
        },
        "us-central1",
    ),
    R(
        AI + "tuningJobs/tj",
        "aiplatform.googleapis.com/TuningJob",
        {
            "supervisedTuningSpec": {"trainingDatasetUri": "gs://media-bkt/tune.jsonl"},
            "baseModel": "gemini",
        },
        "us-central1",
    ),
    R(
        AI + "featureGroups/fg",
        "aiplatform.googleapis.com/FeatureGroup",
        {"bigQuery": {"bigQuerySource": {"inputUri": "bq://proj-a.ds.base"}}},
        "us-central1",
    ),
    R(
        AI + "featureOnlineStores/fos",
        "aiplatform.googleapis.com/FeatureOnlineStore",
        {
            "optimized": {},
            "dedicatedServingEndpoint": {
                "publicEndpointDomainName": "x.featurestore.vertexai.goog"
            },
        },
        "us-central1",
    ),
    R(
        AI + "featurestores/fs",
        "aiplatform.googleapis.com/Featurestore",
        {"onlineServingConfig": {"fixedNodeCount": 1}},
        "us-central1",
    ),
    R(
        AI + "notebookRuntimeTemplates/nrt",
        "aiplatform.googleapis.com/NotebookRuntimeTemplate",
        {"networkSpec": {"subnetwork": SL + "regions/us-central1/subnetworks/sub1"}},
        "us-central1",
    ),
    R(
        AI + "notebookRuntimes/nr",
        "aiplatform.googleapis.com/NotebookRuntime",
        {
            "notebookRuntimeTemplateRef": {
                "notebookRuntimeTemplate": "projects/proj-a/locations/us-central1/notebookRuntimeTemplates/nrt"
            }
        },
        "us-central1",
    ),
    # --- governance
    R(
        f"{CRM}tagKeys/1",
        "cloudresourcemanager.googleapis.com/TagKey",
        {"parent": "organizations/999", "shortName": "env", "namespacedName": "999/env"},
    ),
    R(
        f"{CRM}tagValues/2",
        "cloudresourcemanager.googleapis.com/TagValue",
        {"parent": "tagKeys/1", "shortName": "prod", "namespacedName": "999/env/prod"},
    ),
    R(
        f"{CRM}tagBindings/x",
        "cloudresourcemanager.googleapis.com/TagBinding",
        {"parent": BKT, "tagValue": "tagValues/2", "tagValueNamespacedName": "999/env/prod"},
    ),
    R(
        f"{CRM}liens/l1",
        "cloudresourcemanager.googleapis.com/Lien",
        {"parent": "projects/111", "restrictions": ["resourcemanager.projects.delete"]},
    ),
    R(
        "//orgpolicy.googleapis.com/organizations/999/customConstraints/custom.noPublicIp",
        "orgpolicy.googleapis.com/CustomConstraint",
        {"actionType": "DENY", "resourceTypes": ["compute.googleapis.com/Instance"]},
        ancestors=["organizations/999"],
    ),
    R(
        "//orgpolicy.googleapis.com/projects/proj-a/policies/custom.noPublicIp",
        "orgpolicy.googleapis.com/Policy",
        {"spec": {"rules": [{"enforce": True}]}},
    ),
    R(
        "//assuredworkloads.googleapis.com/organizations/999/locations/us/workloads/w",
        "assuredworkloads.googleapis.com/Workload",
        {
            "complianceRegime": "FEDRAMP_MODERATE",
            "resources": [{"resourceId": "111", "resourceType": "CONSUMER_PROJECT"}],
        },
        "us",
        ancestors=["organizations/999"],
    ),
    R(
        "//accesscontextmanager.googleapis.com/accessPolicies/1/authorizedOrgsDescs/d",
        "accesscontextmanager.googleapis.com/AuthorizedOrgsDesc",
        {"orgs": ["organizations/888"], "authorizationType": "AUTHORIZATION_TYPE_TRUST"},
        ancestors=["organizations/999"],
    ),
    R(
        "//accesscontextmanager.googleapis.com/accessPolicies/1/servicePerimeters/p",
        "accesscontextmanager.googleapis.com/ServicePerimeter",
        {
            "status": {
                "accessLevels": ["accessPolicies/1/accessLevels/corp"],
                "resources": ["projects/111"],
            }
        },
        ancestors=["organizations/999"],
    ),
    R(
        "//accesscontextmanager.googleapis.com/accessPolicies/1/accessLevels/corp",
        "accesscontextmanager.googleapis.com/AccessLevel",
        {"title": "corp", "basic": {"conditions": [{"ipSubnetworks": ["203.0.113.0/24"]}]}},
        ancestors=["organizations/999"],
    ),
    R(
        "//config.googleapis.com/projects/proj-a/locations/us-central1/deployments/im",
        "config.googleapis.com/Deployment",
        {
            "serviceAccount": f"projects/{PROJECT}/serviceAccounts/{APP_SA}",
            "terraformBlueprint": {"gcsSource": "gs://media-bkt/bp"},
            "latestRevision": "projects/proj-a/locations/us-central1/deployments/im/revisions/r-1",
        },
        "us-central1",
    ),
    R(
        "//config.googleapis.com/projects/proj-a/locations/us-central1/previews/pv",
        "config.googleapis.com/Preview",
        {"deployment": "projects/proj-a/locations/us-central1/deployments/im"},
        "us-central1",
    ),
    # --- ops
    R(
        "//monitoring.googleapis.com/projects/proj-a/alertPolicies/1",
        "monitoring.googleapis.com/AlertPolicy",
        {
            "conditions": [
                {
                    "conditionThreshold": {
                        "filter": 'resource.type = "gcs_bucket" AND resource.labels.bucket_name = "media-bkt"'
                    }
                }
            ],
            "notificationChannels": ["projects/proj-a/notificationChannels/9"],
        },
    ),
    R(
        "//monitoring.googleapis.com/projects/proj-a/notificationChannels/9",
        "monitoring.googleapis.com/NotificationChannel",
        {"type": "pubsub", "labels": {"topic": "projects/proj-a/topics/ch-topic"}},
    ),
    R(
        "//monitoring.googleapis.com/projects/proj-a/uptimeCheckConfigs/up",
        "monitoring.googleapis.com/UptimeCheckConfig",
        {
            "monitoredResource": {
                "type": "uptime_url",
                "labels": {"host": "orders-abc-uc.a.run.app"},
            },
            "httpCheck": {},
        },
    ),
    R(
        "//osconfig.googleapis.com/projects/proj-a/patchDeployments/weekly",
        "osconfig.googleapis.com/PatchDeployment",
        {
            "instanceFilter": {"groupLabels": [{"labels": {"env": "prod"}}]},
            "recurringSchedule": {"frequency": "WEEKLY"},
        },
    ),
    R(
        "//osconfig.googleapis.com/projects/proj-a/locations/us-central1-a/osPolicyAssignments/agents",
        "osconfig.googleapis.com/OSPolicyAssignment",
        {
            "instanceFilter": {"inclusionLabels": [{"labels": {"env": "prod"}}]},
            "osPolicies": [{"id": "ops-agent", "mode": "ENFORCEMENT"}],
        },
        "us-central1-a",
    ),
    R(
        "//osconfig.googleapis.com/projects/111/locations/us-central1-a/instances/4242/vulnerabilityReport",
        "osconfig.googleapis.com/VulnerabilityReport",
        {"vulnerabilities": [{"details": {"cve": "CVE-2026-0001", "severity": "HIGH"}}]},
        "us-central1-a",
    ),
    R(
        BDR + "backupVaults/v",
        "backupdr.googleapis.com/BackupVault",
        {
            "serviceAccount": "vault@gcp-sa-backupdr.iam.gserviceaccount.com",
            "backupMinimumEnforcedRetentionDuration": "86400s",
        },
        "us-central1",
    ),
    R(
        BDR + "backupPlans/p",
        "backupdr.googleapis.com/BackupPlan",
        {
            "backupVault": "projects/proj-a/locations/us-central1/backupVaults/v",
            "resourceType": "compute.googleapis.com/Instance",
            "backupRules": [{"ruleId": "daily", "backupRetentionDays": 7}],
        },
        "us-central1",
    ),
    R(
        BDR + "backupPlanAssociations/a",
        "backupdr.googleapis.com/BackupPlanAssociation",
        {
            "resource": "projects/proj-a/zones/us-central1-a/instances/st-vm",
            "resourceType": "compute.googleapis.com/Instance",
            "backupPlan": "projects/proj-a/locations/us-central1/backupPlans/p",
        },
        "us-central1",
    ),
    R(
        BDR + "backupVaults/v/dataSources/ds1",
        "backupdr.googleapis.com/DataSource",
        {
            "dataSourceGcpResource": {
                "gcpResourcename": "projects/proj-a/zones/us-central1-a/instances/st-vm",
                "type": "compute.googleapis.com/Instance",
            }
        },
        "us-central1",
    ),
    R(
        BDR + "backupVaults/v/dataSources/ds1/backups/b",
        "backupdr.googleapis.com/Backup",
        {"backupType": "SCHEDULED"},
        "us-central1",
    ),
    R(
        BDR + "managementServers/ms",
        "backupdr.googleapis.com/ManagementServer",
        {"networks": [{"network": SL + "global/networks/net1"}]},
        "us-central1",
    ),
    # --- security
    R(
        "//securitycenter.googleapis.com/organizations/999/notificationConfigs/n",
        "securitycenter.googleapis.com/NotificationConfig",
        {
            "pubsubTopic": "projects/proj-a/topics/ch-topic",
            "streamingConfig": {"filter": 'state = "ACTIVE"'},
        },
        ancestors=["organizations/999"],
    ),
    R(
        "//securitycenter.googleapis.com/projects/proj-a/bigQueryExports/e",
        "securitycenter.googleapis.com/BigQueryExport",
        {"dataset": "projects/proj-a/datasets/ds"},
    ),
    R(
        "//securitycenter.googleapis.com/projects/proj-a/muteConfigs/m",
        "securitycenter.googleapis.com/MuteConfig",
        {"filter": 'category = "X"'},
    ),
    R(
        "//securitycenter.googleapis.com/projects/proj-a/eventThreatDetectionSettings",
        "securitycenter.googleapis.com/EventThreatDetectionSettings",
        {"serviceEnablementState": "ENABLED"},
    ),
    R(
        "//dlp.googleapis.com/projects/proj-a/locations/global/discoveryConfigs/dc",
        "dlp.googleapis.com/DiscoveryConfig",
        {
            "status": "RUNNING",
            "actions": [{"pubSubNotification": {"topic": "projects/proj-a/topics/ch-topic"}}],
            "targets": [{"bigQueryTarget": {}}],
        },
    ),
    R(
        "//dlp.googleapis.com/projects/proj-a/locations/global/jobTriggers/jt",
        "dlp.googleapis.com/JobTrigger",
        {
            "inspectJob": {
                "storageConfig": {"cloudStorageOptions": {"fileSet": {"url": "gs://media-bkt/**"}}},
                "actions": [
                    {
                        "saveFindings": {
                            "outputConfig": {
                                "table": {"projectId": "proj-a", "datasetId": "ds", "tableId": "f"}
                            }
                        }
                    }
                ],
            }
        },
    ),
    R(
        "//dlp.googleapis.com/projects/proj-a/locations/global/inspectTemplates/it",
        "dlp.googleapis.com/InspectTemplate",
        {"inspectConfig": {"infoTypes": [{"name": "EMAIL_ADDRESS"}]}},
    ),
    # --- identity
    R(
        "//iam.googleapis.com/locations/global/workforcePools/wf",
        "iam.googleapis.com/WorkforcePool",
        {"parent": "organizations/999", "sessionDuration": "3600s"},
        ancestors=["organizations/999"],
    ),
    R(
        f"//iam.googleapis.com/projects/{NUMBER}/locations/global/workloadIdentityPools/gh",
        "iam.googleapis.com/WorkloadIdentityPool",
        {"mode": "FEDERATION_ONLY"},
    ),
    R(
        "//iam.googleapis.com/policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fproj-a/denypolicies/no-delete",
        "iam.googleapis.com/PolicyV2",
        {
            "kind": "DenyPolicy",
            "rules": [
                {
                    "denyRule": {
                        "deniedPrincipals": ["principalSet://goog/group/devs@example.com"],
                        "deniedPermissions": ["resourcemanager.projects.delete"],
                    }
                }
            ],
        },
    ),
    R(
        "//iam.googleapis.com/organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
        "iam.googleapis.com/PrincipalAccessBoundaryPolicy",
        {"details": {"rules": [{"resources": [ORG], "effect": "ALLOW"}]}},
        ancestors=["organizations/999"],
    ),
    R(
        "//iam.googleapis.com/organizations/999/locations/global/policyBindings/b",
        "iam.googleapis.com/PolicyBinding",
        {
            "target": {"principalSet": "//iam.googleapis.com/locations/global/workforcePools/wf"},
            "policy": "organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
            "policyKind": "PRINCIPAL_ACCESS_BOUNDARY",
        },
        ancestors=["organizations/999"],
    ),
    R(
        "//privilegedaccessmanager.googleapis.com/projects/proj-a/locations/global/entitlements/break-glass",
        "privilegedaccessmanager.googleapis.com/Entitlement",
        {
            "eligibleUsers": [{"principals": ["user:alice@example.com"]}],
            "privilegedAccess": {
                "gcpIamAccess": {
                    "resourceType": "cloudresourcemanager.googleapis.com/Project",
                    "resource": f"{CRM}projects/proj-a",
                    "roleBindings": [{"role": "roles/owner"}],
                }
            },
            "approvalWorkflow": {
                "manualApprovals": {
                    "steps": [{"approvers": [{"principals": ["group:sec@example.com"]}]}]
                }
            },
        },
    ),
    R(
        "//iam.googleapis.com/projects/proj-a/oauthClients/oc",
        "iam.googleapis.com/OauthClient",
        {"clientType": "CONFIDENTIAL_CLIENT", "allowedGrantTypes": ["AUTHORIZATION_CODE_GRANT"]},
    ),
    R(
        "//iam.googleapis.com/projects/proj-a/oauthClients/oc/credentials/c",
        "iam.googleapis.com/OauthClientCredential",
        {},
    ),
    R(
        "//iam.googleapis.com/projects/proj-a/roles/deployer",
        "iam.googleapis.com/Role",
        {"includedPermissions": ["run.services.update"], "stage": "GA"},
    ),
    # --- CI/CD
    R(
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/workerPools/wp",
        "cloudbuild.googleapis.com/WorkerPool",
        {
            "privatePoolV1Config": {
                "networkConfig": {
                    "peeredNetwork": "projects/111/global/networks/net1",
                    "egressOption": "NO_PUBLIC_EGRESS",
                }
            }
        },
        "us-central1",
    ),
    R(
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/connections/gh",
        "cloudbuild.googleapis.com/Connection",
        {
            "githubConfig": {
                "authorizerCredential": {
                    "oauthTokenSecretVersion": "projects/proj-a/secrets/gh-token/versions/1"
                }
            }
        },
        "us-central1",
    ),
    R(
        "//secretmanager.googleapis.com/projects/proj-a/secrets/gh-token",
        "secretmanager.googleapis.com/Secret",
        {},
    ),
    R(
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/connections/gh/repositories/app",
        "cloudbuild.googleapis.com/Repository",
        {"remoteUri": "https://github.com/org/app.git"},
        "us-central1",
    ),
    R(
        "//developerconnect.googleapis.com/projects/proj-a/locations/us-central1/connections/dc",
        "developerconnect.googleapis.com/Connection",
        {
            "githubConfig": {
                "authorizerCredential": {
                    "oauthTokenSecretVersion": "projects/proj-a/secrets/gh-token/versions/2"
                }
            }
        },
        "us-central1",
    ),
    R(
        "//developerconnect.googleapis.com/projects/proj-a/locations/us-central1/connections/dc/gitRepositoryLinks/l",
        "developerconnect.googleapis.com/GitRepositoryLink",
        {"cloneUri": "https://github.com/org/app.git"},
        "us-central1",
    ),
    R(
        "//developerconnect.googleapis.com/projects/proj-a/locations/us-central1/insightsConfigs/ic",
        "developerconnect.googleapis.com/InsightsConfig",
        {"artifactConfigs": [{"uri": "projects/proj-a/locations/us/repositories/repo"}]},
        "us-central1",
    ),
    R(
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/triggers/deploy",
        "cloudbuild.googleapis.com/BuildTrigger",
        {
            "serviceAccount": f"projects/{PROJECT}/serviceAccounts/{APP_SA}",
            "repositoryEventConfig": {
                "repository": "projects/proj-a/locations/us-central1/connections/gh/repositories/app"
            },
            "build": {
                "options": {
                    "pool": {"name": "projects/proj-a/locations/us-central1/workerPools/wp"}
                }
            },
        },
        "us-central1",
    ),
]

IAM = [
    {
        "resource": BKT,
        "policy": {
            "bindings": [
                {"role": "projects/proj-a/roles/deployer", "members": ["user:bob@example.com"]},
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["group:readers@example.com", f"serviceAccount:{APP_SA}"],
                },
            ]
        },
    }
]

# (source, target, edge type, relationship); names that are not records get stubs
CASES = [
    # hybrid
    (HUB, NET1, E.ROUTE, "TRANSIT_ROUTED"),
    (HUB, HUB + "/routeTables/rt", E.CONTAINS, None),
    (HUB, HUB + "/groups/g", E.CONTAINS, None),
    (
        "//networkconnectivity.googleapis.com/projects/proj-a/locations/global/internalRanges/ir",
        NET1,
        E.ATTACHED_TO,
        None,
    ),
    (
        "//networkconnectivity.googleapis.com/projects/proj-a/locations/global/policyBasedRoutes/pbr",
        C + "regions/us-central1/addresses/ilb",
        E.ROUTE,
        "TRANSIT_ROUTED",
    ),
    (
        "//networkconnectivity.googleapis.com/projects/proj-a/locations/us-central1/regionalEndpoints/re",
        NET1,
        E.ATTACHED_TO,
        None,
    ),
    (
        C + "global/interconnects/ic",
        C + "regions/us-central1/interconnectAttachments/att",
        E.CONTAINS,
        None,
    ),
    (
        C + "regions/us-central1/vpnTunnels/t1",
        C + "global/externalVpnGateways/evg",
        E.ROUTE,
        "TRANSIT_ROUTED",
    ),
    (
        f"{CRM}projects/proj-c",
        C + "regions/us-central1/serviceAttachments/sa1",
        E.GRANTS_ACCESS,
        "CROSS_ACCOUNT_TRUST",
    ),
    (C + "regions/us-central1/packetMirrorings/pm", SUB1, E.MONITORS, "MONITORED_BY"),
    (C + "regions/us-central1/packetMirrorings/pm", IDS, E.INVOKES, "STREAMS_TO"),
    (
        C + "zones/us-central1-a/nodeGroups/ng",
        C + "regions/us-central1/nodeTemplates/nt",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (VM, C + "zones/us-central1-a/nodeGroups/ng", E.REFERENCES, "RUNS_ON"),
    (SCHED_POLICY, VM, E.MANAGES, "SCHEDULED_BY"),
    (SNAP_POLICY, C + "zones/us-central1-a/disks/d1", E.MANAGES, "BACKUP_TO"),
    # network security and services
    (
        NSEC + "organizations/999/locations/us-central1-a/firewallEndpoints/fe",
        NET1,
        E.PROTECTS,
        "PROTECTED_BY_NACL",
    ),
    (
        NSEC + "projects/proj-a/locations/us-central1-a/firewallEndpointAssociations/a",
        NET2,
        E.PROTECTS,
        "PROTECTED_BY_NACL",
    ),
    (
        NSEC + "projects/proj-a/locations/us-central1-a/firewallEndpointAssociations/a",
        NSEC + "organizations/999/locations/us-central1-a/firewallEndpoints/fe",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        NSEC + "organizations/999/locations/global/securityProfileGroups/spg",
        NSEC + "organizations/999/locations/global/securityProfiles/sp",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        NSEC + "projects/proj-a/locations/us-central1/tlsInspectionPolicies/tip",
        POOL,
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        NSEC + "projects/proj-a/locations/global/serverTlsPolicies/stp",
        CM + "trustConfigs/tc",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        NSEC + "projects/proj-a/locations/global/authzPolicies/az",
        C + "global/forwardingRules/fr1",
        E.PROTECTS,
        "PROTECTED_BY_WAF",
    ),
    (
        C + "global/firewallPolicies/fwp",
        NSEC + "organizations/999/locations/global/securityProfileGroups/spg",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (IDS, NET1, E.PROTECTS, "PROTECTED_BY_NACL"),
    (NSVC + "gateways/swp", CM + "certificates/c1", E.REFERENCES, "CERTIFICATE_SECURES"),
    (NSVC + "gateways/swp", NET1, E.ATTACHED_TO, None),
    (NSVC + "httpRoutes/hr", C + "global/backendServices/bs1", E.ROUTE, "SERVES_TRAFFIC_TO"),
    (NSVC + "httpRoutes/hr", NSVC + "gateways/swp", E.ATTACHED_TO, None),
    (
        NSVC + "serviceBindings/sb",
        "//servicedirectory.googleapis.com/projects/proj-a/locations/us-central1/namespaces/ns/services/svc",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        NSVC + "endpointPolicies/ep",
        NSEC + "projects/proj-a/locations/global/serverTlsPolicies/stp",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (NSVC + "edgeCacheServices/cdn", NSVC + "edgeCacheOrigins/o1", E.ROUTE, "SERVES_TRAFFIC_TO"),
    (
        C + "global/securityPolicies/armor",
        NSVC + "edgeCacheServices/cdn",
        E.PROTECTS,
        "PROTECTED_BY_WAF",
    ),
    (NSVC + "edgeCacheOrigins/o1", BKT, E.ROUTE, "SERVES_TRAFFIC_TO"),
    (NSVC + "edgeCacheKeysets/ks", SECRET, E.REFERENCES, "READS_FROM"),
    (
        C + "regions/us-central1/networkEdgeSecurityServices/ness",
        C + "global/securityPolicies/armor",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    # edge
    (CM + "certificates/c1", CM + "dnsAuthorizations/da", E.REFERENCES, "DEPENDS_ON"),
    (
        C + "global/targetHttpsProxies/px",
        CM + "certificateMaps/map",
        E.REFERENCES,
        "CERTIFICATE_SECURES",
    ),
    (
        CM + "certificateMaps/map",
        CM + "certificateMaps/map/certificateMapEntries/e",
        E.CONTAINS,
        None,
    ),
    (
        CM + "certificateMaps/map/certificateMapEntries/e",
        CM + "certificates/c1",
        E.REFERENCES,
        "CERTIFICATE_SECURES",
    ),
    (CM + "certificateIssuanceConfigs/ic", POOL, E.REFERENCES, "DEPENDS_ON"),
    (POOL, POOL + "/certificateAuthorities/ca1", E.CONTAINS, None),
    (POOL + "/certificateAuthorities/ca1", BKT, E.REFERENCES, "WRITES_TO"),
    (
        "//run.googleapis.com/projects/proj-a/locations/us-central1/domainmappings/api.example.com",
        RUN,
        E.ROUTE,
        "SERVES_TRAFFIC_TO",
    ),
    (
        "//identitytoolkit.googleapis.com/projects/proj-a/config",
        "//cloudfunctions.googleapis.com/projects/proj-a/locations/us-central1/functions/block",
        E.INVOKES,
        "INVOKES",
    ),
    (
        "//identitytoolkit.googleapis.com/projects/proj-a/config",
        "//identitytoolkit.googleapis.com/projects/proj-a/tenants/t1",
        E.CONTAINS,
        None,
    ),
    (
        "//identitytoolkit.googleapis.com/projects/proj-a/config",
        "//identitytoolkit.googleapis.com/projects/proj-a/oauthIdpConfigs/oidc.corp",
        E.CONTAINS,
        None,
    ),
    # APIs
    (APIGEE, NET1, E.ATTACHED_TO, None),
    (APIGEE, APIGEE + "/instances/i1", E.CONTAINS, None),
    (
        APIGEE + "/instances/i1",
        C + "regions/us-central1/serviceAttachments/sa1",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (APIGEE, APIGEE + "/environments/prod", E.CONTAINS, None),
    (APIGEE, APIGEE + "/apis/orders", E.CONTAINS, None),
    (APIGEE + "/apis/orders", APIGEE + "/apis/orders/revisions/1", E.CONTAINS, None),
    (
        "//apigateway.googleapis.com/projects/proj-a/locations/global/apis/orders/configs/v1",
        RUN,
        E.ROUTE,
        "SERVES_TRAFFIC_TO",
    ),
    # containers
    (REPO, REPO + "/dockerImages/img@sha256:abc", E.CONTAINS, None),
    (REPO + "-virtual", REPO, E.REFERENCES, "READS_FROM"),
    (
        "//binaryauthorization.googleapis.com/projects/proj-a/policy",
        CR,
        E.GOVERNS,
        "COMPLIANCE_GOVERNS",
    ),
    (
        "//binaryauthorization.googleapis.com/projects/proj-a/policy",
        "//binaryauthorization.googleapis.com/projects/proj-a/attestors/att",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//binaryauthorization.googleapis.com/projects/proj-a/attestors/att",
        "gcp-principal:serviceAccount:attestor@proj-a.iam.gserviceaccount.com",
        E.ASSUMES_ROLE,
        "RUNS_ON",
    ),
    (
        "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1",
        CR,
        E.MANAGES,
        "OWNED_BY",
    ),
    (
        "//gkehub.googleapis.com/projects/proj-a/locations/global/features/configmanagement",
        "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1",
        E.MANAGES,
        "OWNED_BY",
    ),
    (
        "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1",
        "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1/bindings/b1",
        E.CONTAINS,
        None,
    ),
    (
        "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1/bindings/b1",
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team",
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team/namespaces/ns1",
        E.CONTAINS,
        None,
    ),
    (
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team",
        "//gkehub.googleapis.com/projects/proj-a/locations/global/scopes/team/rbacrolebindings/rb",
        E.CONTAINS,
        None,
    ),
    (
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/backupPlans/bp",
        CR,
        E.MANAGES,
        "BACKUP_TO",
    ),
    (
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/backupPlans/bp",
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/backupPlans/bp/backups/b",
        E.CONTAINS,
        None,
    ),
    (
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/restorePlans/rp",
        "//gkebackup.googleapis.com/projects/proj-a/locations/us-central1/backupPlans/bp",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (CR, CR + "/k8s/namespaces/team", E.CONTAINS, "CLUSTER_CONTAINS_SERVICE"),
    (CR, CR + "/k8s/clusterroles/admin", E.CONTAINS, None),
    # integration
    (
        "//cloudscheduler.googleapis.com/projects/proj-a/locations/us-central1/jobs/nightly",
        WF,
        E.INVOKES,
        "SCHEDULED_BY",
    ),
    (
        "//cloudscheduler.googleapis.com/projects/proj-a/locations/us-central1/jobs/nightly",
        SA_ARN,
        E.ASSUMES_ROLE,
        "RUNS_ON",
    ),
    (
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/channels/ch",
        TOPIC,
        E.INVOKES,
        "STREAMS_TO",
    ),
    (
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/channelConnections/cc",
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/channels/ch",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/channels/ch",
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/triggers/tr",
        E.INVOKES,
        "TRIGGERED_BY",
    ),
    (
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/googleApiSources/src",
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/messageBuses/bus",
        E.INVOKES,
        "STREAMS_TO",
    ),
    (
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/messageBuses/bus",
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/enrollments/en",
        E.INVOKES,
        "TRIGGERED_BY",
    ),
    (
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/enrollments/en",
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/pipelines/pl",
        E.INVOKES,
        "INVOKES",
    ),
    (
        "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/pipelines/pl",
        WF,
        E.INVOKES,
        "INVOKES",
    ),
    (KAFKA, KAFKA + "/topics/orders", E.CONTAINS, None),
    (KAFKA + "/consumerGroups/cg", KAFKA + "/topics/orders", E.REFERENCES, "READS_FROM"),
    (
        "//managedkafka.googleapis.com/projects/proj-a/locations/us-central1/connectClusters/cc",
        KAFKA,
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//managedkafka.googleapis.com/projects/proj-a/locations/us-central1/connectClusters/cc/connectors/sink",
        TOPIC,
        E.INVOKES,
        "STREAMS_TO",
    ),
    ("//pubsub.googleapis.com/projects/proj-a/snapshots/snap", TOPIC, E.REFERENCES, "DEPENDS_ON"),
    (WF, TOPIC, E.REFERENCES, "WRITES_TO"),
    (WF, SECRET, E.REFERENCES, "READS_FROM"),
    (WF, RUN, E.INVOKES, "INVOKES"),
    (
        "//batch.googleapis.com/projects/proj-a/locations/us-central1/jobs/b1",
        REPO,
        E.USES_IMAGE,
        "RUNS_ON",
    ),
    (
        "//batch.googleapis.com/projects/proj-a/locations/us-central1/jobs/b1",
        BKT,
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        SUB1,
        "//batch.googleapis.com/projects/proj-a/locations/us-central1/jobs/b1",
        E.CONTAINS,
        "SUBNET_CONTAINS_INSTANCE",
    ),
    # data
    (SPANNER, SPANNER + "/databases/db", E.CONTAINS, "CLUSTER_CONTAINS_SERVICE"),
    (SPANNER + "/databases/db", SPANNER + "/backups/bk", E.REFERENCES, "BACKUP_TO"),
    (BT, BT + "/clusters/c1", E.CONTAINS, "CLUSTER_CONTAINS_SERVICE"),
    (BT, BT + "/tables/t1", E.CONTAINS, None),
    (BT + "/tables/t1", BT + "/tables/t1/authorizedViews/v", E.CONTAINS, None),
    (BT + "/tables/t1", BT + "/clusters/c1/backups/b1", E.REFERENCES, "BACKUP_TO"),
    (BT + "/appProfiles/ap", BT + "/clusters/c1", E.ROUTE, "SERVES_TRAFFIC_TO"),
    (
        "//firestore.googleapis.com/projects/proj-a/databases/(default)",
        "//firestore.googleapis.com/projects/proj-a/locations/nam5/backups/fb",
        E.REFERENCES,
        "BACKUP_TO",
    ),
    (DS + "/tables/v1", BASE, E.REFERENCES, "READS_FROM"),
    (DS, DS + "/tables/v1", E.CONTAINS, None),
    (DS + "/routines/r", BASE, E.REFERENCES, "READS_FROM"),
    (DS, DS + "/models/m", E.CONTAINS, None),
    (BASE + "/rowAccessPolicies/rap", BASE, E.GOVERNS, "COMPLIANCE_GOVERNS"),
    (
        "//bigqueryconnection.googleapis.com/projects/proj-a/locations/us/connections/sqlconn",
        "//cloudsql.googleapis.com/projects/proj-a/instances/db1",
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//bigquerydatatransfer.googleapis.com/projects/111/locations/us/transferConfigs/tc",
        DS,
        E.REFERENCES,
        "WRITES_TO",
    ),
    (
        "//bigquerydatatransfer.googleapis.com/projects/111/locations/us/transferConfigs/tc",
        BKT,
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake",
        "//metastore.googleapis.com/projects/proj-a/locations/us-central1/services/ms",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake",
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake/zones/raw",
        E.CONTAINS,
        None,
    ),
    (
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake/zones/raw/assets/a",
        BKT,
        E.GOVERNS,
        "COMPLIANCE_GOVERNS",
    ),
    (
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/lakes/lake/tasks/t",
        BKT,
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//dataplex.googleapis.com/projects/proj-a/locations/us-central1/dataScans/dq",
        BASE,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        "//metastore.googleapis.com/projects/proj-a/locations/us-central1/services/ms",
        NET1,
        E.ATTACHED_TO,
        None,
    ),
    (
        "//datafusion.googleapis.com/projects/proj-a/locations/us-central1/instances/df",
        NET1,
        E.ATTACHED_TO,
        None,
    ),
    (
        "//datafusion.googleapis.com/projects/proj-a/locations/us-central1/instances/df/dnsPeerings/p",
        NET1,
        E.ROUTE,
        "DNS_RESOLVED",
    ),
    (
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/streams/s",
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/connectionProfiles/src",
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/streams/s",
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/connectionProfiles/dst",
        E.INVOKES,
        "STREAMS_TO",
    ),
    (
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/connectionProfiles/dst",
        BKT,
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/connectionProfiles/src",
        C + "regions/us-central1/addresses/ilb",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//datastream.googleapis.com/projects/proj-a/locations/us-central1/privateConnections/pc",
        NET1,
        E.PEERING,
        "VPC_PEERED",
    ),
    ("//storagetransfer.googleapis.com/transferJobs/123", BKT, E.REFERENCES, "READS_FROM"),
    ("//storagetransfer.googleapis.com/transferJobs/123", SINK, E.REFERENCES, "WRITES_TO"),
    (NETAPP + "storagePools/pool", NET1, E.ATTACHED_TO, None),
    (NETAPP + "storagePools/pool", NETAPP + "volumes/vol", E.CONTAINS, None),
    (NETAPP + "volumes/vol", NETAPP + "backupVaults/nv", E.REFERENCES, "BACKUP_TO"),
    (
        NETAPP + "volumes/vol/replications/r",
        "//netapp.googleapis.com/projects/proj-a/locations/us-east1/volumes/dr",
        E.REFERENCES,
        "REPLICATES_TO",
    ),
    (NETAPP + "volumes/vol", NETAPP + "backupVaults/nv/backups/b", E.REFERENCES, "BACKUP_TO"),
    (NETAPP + "backupVaults/nv", NETAPP + "backupVaults/nv/backups/b", E.CONTAINS, None),
    (NETAPP + "volumes/vol", NETAPP + "volumes/vol/snapshots/s", E.REFERENCES, "BACKUP_TO"),
    (
        "//file.googleapis.com/projects/proj-a/locations/us-central1-a/instances/fs",
        "//file.googleapis.com/projects/proj-a/locations/us-central1/backups/fsb",
        E.REFERENCES,
        "BACKUP_TO",
    ),
    (
        "//secretmanager.googleapis.com/projects/proj-a/secrets/rotating",
        "//cloudfunctions.googleapis.com/projects/proj-a/locations/us-central1/functions/rotator",
        E.INVOKES,
        "ROTATES_SECRET",
    ),
    (
        "//parametermanager.googleapis.com/projects/proj-a/locations/global/parameters/cfg",
        "//parametermanager.googleapis.com/projects/proj-a/locations/global/parameters/cfg/versions/v1",
        E.CONTAINS,
        None,
    ),
    # ML
    (AI + "reasoningEngines/agent", BKT, E.REFERENCES, "READS_FROM"),
    (AI + "reasoningEngines/agent", SECRET, E.REFERENCES, "READS_FROM"),
    (AI + "reasoningEngines/agent", SA_ARN, E.ASSUMES_ROLE, "RUNS_ON"),
    (AI + "indexes/idx", BKT, E.REFERENCES, "READS_FROM"),
    (AI + "indexEndpoints/ie", AI + "indexes/idx", E.ROUTE, "SERVES_TRAFFIC_TO"),
    (DE, DE + "/dataStores/kb", E.CONTAINS, None),
    (DE + "/engines/e", DE + "/dataStores/kb", E.REFERENCES, "READS_FROM"),
    (DE + "/engines/e", DE + "/engines/e/assistants/a", E.CONTAINS, None),
    (
        "//dialogflow.googleapis.com/projects/proj-a/locations/global/agents/bot",
        "//dialogflow.googleapis.com/projects/proj-a/locations/global/securitySettings/ss",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (AI + "customJobs/cj", REPO, E.USES_IMAGE, "RUNS_ON"),
    (AI + "customJobs/cj", SINK, E.REFERENCES, "WRITES_TO"),
    (AI + "hyperparameterTuningJobs/hp", REPO, E.USES_IMAGE, "RUNS_ON"),
    (AI + "datasets/777", BKT, E.REFERENCES, "READS_FROM"),
    (AI + "trainingPipelines/tp", AI + "datasets/777", E.REFERENCES, "READS_FROM"),
    (AI + "pipelineJobs/pj", SINK, E.REFERENCES, "WRITES_TO"),
    (AI + "batchPredictionJobs/bp", BASE, E.REFERENCES, "READS_FROM"),
    (AI + "batchPredictionJobs/bp", SINK, E.REFERENCES, "WRITES_TO"),
    (AI + "tuningJobs/tj", BKT, E.REFERENCES, "READS_FROM"),
    (AI + "featureGroups/fg", BASE, E.REFERENCES, "READS_FROM"),
    (SUB1, AI + "notebookRuntimeTemplates/nrt", E.CONTAINS, "SUBNET_CONTAINS_INSTANCE"),
    (AI + "notebookRuntimes/nr", AI + "notebookRuntimeTemplates/nrt", E.REFERENCES, "DEPENDS_ON"),
    # governance
    (ORG, f"{CRM}tagKeys/1", E.CONTAINS, None),
    (f"{CRM}tagKeys/1", f"{CRM}tagValues/2", E.CONTAINS, None),
    (BKT, f"{CRM}tagValues/2", E.REFERENCES, "TAGGED_WITH"),
    (f"{CRM}liens/l1", PROJ, E.GOVERNS, "COMPLIANCE_GOVERNS"),
    (
        "//orgpolicy.googleapis.com/projects/proj-a/policies/custom.noPublicIp",
        "//orgpolicy.googleapis.com/organizations/999/customConstraints/custom.noPublicIp",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//assuredworkloads.googleapis.com/organizations/999/locations/us/workloads/w",
        PROJ,
        E.GOVERNS,
        "COMPLIANCE_GOVERNS",
    ),
    (
        "//accesscontextmanager.googleapis.com/accessPolicies/1/authorizedOrgsDescs/d",
        f"{CRM}organizations/888",
        E.GRANTS_ACCESS,
        "CROSS_ACCOUNT_TRUST",
    ),
    (
        "//accesscontextmanager.googleapis.com/accessPolicies/1/servicePerimeters/p",
        "//accesscontextmanager.googleapis.com/accessPolicies/1/accessLevels/corp",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//config.googleapis.com/projects/proj-a/locations/us-central1/deployments/im",
        BKT,
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//config.googleapis.com/projects/proj-a/locations/us-central1/deployments/im",
        SA_ARN,
        E.ASSUMES_ROLE,
        "RUNS_ON",
    ),
    (
        "//config.googleapis.com/projects/proj-a/locations/us-central1/previews/pv",
        "//config.googleapis.com/projects/proj-a/locations/us-central1/deployments/im",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (CR, BKT, E.MANAGES, "OWNED_BY"),  # managed-by-cnrm label, see BKT_KCC below
    # ops
    (
        "//monitoring.googleapis.com/projects/proj-a/alertPolicies/1",
        BKT,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        "//monitoring.googleapis.com/projects/proj-a/alertPolicies/1",
        "//monitoring.googleapis.com/projects/proj-a/notificationChannels/9",
        E.INVOKES,
        "INVOKES",
    ),
    (
        "//monitoring.googleapis.com/projects/proj-a/notificationChannels/9",
        TOPIC,
        E.INVOKES,
        "INVOKES",
    ),
    (
        "//monitoring.googleapis.com/projects/proj-a/uptimeCheckConfigs/up",
        RUN,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        "//osconfig.googleapis.com/projects/proj-a/patchDeployments/weekly",
        VM,
        E.MANAGES,
        "SCHEDULED_BY",
    ),
    (
        "//osconfig.googleapis.com/projects/proj-a/locations/us-central1-a/osPolicyAssignments/agents",
        VM,
        E.MANAGES,
        "SCHEDULED_BY",
    ),
    (
        "//osconfig.googleapis.com/projects/111/locations/us-central1-a/instances/4242/vulnerabilityReport",
        VM,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        BDR + "backupVaults/v",
        "gcp-principal:serviceAccount:vault@gcp-sa-backupdr.iam.gserviceaccount.com",
        E.ASSUMES_ROLE,
        "RUNS_ON",
    ),
    (BDR + "backupPlans/p", BDR + "backupVaults/v", E.REFERENCES, "BACKUP_TO"),
    (BDR + "backupPlanAssociations/a", VM, E.MANAGES, "BACKUP_TO"),
    (BDR + "backupPlanAssociations/a", BDR + "backupPlans/p", E.REFERENCES, "DEPENDS_ON"),
    (BDR + "backupVaults/v", BDR + "backupVaults/v/dataSources/ds1", E.CONTAINS, None),
    (VM, BDR + "backupVaults/v/dataSources/ds1", E.REFERENCES, "BACKUP_TO"),
    (
        BDR + "backupVaults/v/dataSources/ds1",
        BDR + "backupVaults/v/dataSources/ds1/backups/b",
        E.CONTAINS,
        None,
    ),
    (BDR + "managementServers/ms", NET1, E.ATTACHED_TO, None),
    # security
    (
        "//securitycenter.googleapis.com/organizations/999/notificationConfigs/n",
        TOPIC,
        E.INVOKES,
        "STREAMS_TO",
    ),
    (
        "//securitycenter.googleapis.com/projects/proj-a/bigQueryExports/e",
        DS,
        E.INVOKES,
        "STREAMS_TO",
    ),
    (
        "//securitycenter.googleapis.com/projects/proj-a/eventThreatDetectionSettings",
        PROJ,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        "//dlp.googleapis.com/projects/proj-a/locations/global/discoveryConfigs/dc",
        PROJ,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        "//dlp.googleapis.com/projects/proj-a/locations/global/discoveryConfigs/dc",
        TOPIC,
        E.INVOKES,
        "INVOKES",
    ),
    (
        "//dlp.googleapis.com/projects/proj-a/locations/global/jobTriggers/jt",
        BKT,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        "//dlp.googleapis.com/projects/proj-a/locations/global/jobTriggers/jt",
        DS,
        E.REFERENCES,
        "WRITES_TO",
    ),
    # identity
    (ORG, "//iam.googleapis.com/locations/global/workforcePools/wf", E.CONTAINS, None),
    (
        "//iam.googleapis.com/policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fproj-a/denypolicies/no-delete",
        PROJ,
        E.GOVERNS,
        "POLICY_DENIES_ACTION",
    ),
    (
        "//iam.googleapis.com/policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fproj-a/denypolicies/no-delete",
        "gcp-principal:group:devs@example.com",
        E.GOVERNS,
        "POLICY_DENIES_ACTION",
    ),
    (
        "//iam.googleapis.com/organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
        ORG,
        E.GOVERNS,
        "PERMISSION_BOUNDARY_LIMITS",
    ),
    (
        "//iam.googleapis.com/locations/global/workforcePools/wf",
        "//iam.googleapis.com/organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
        E.REFERENCES,
        "PERMISSION_BOUNDARY_LIMITS",
    ),
    (
        "//iam.googleapis.com/organizations/999/locations/global/policyBindings/b",
        "//iam.googleapis.com/organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//privilegedaccessmanager.googleapis.com/projects/proj-a/locations/global/entitlements/break-glass",
        PROJ,
        E.GRANTS_ACCESS,
        "POLICY_ALLOWS_ACTION",
    ),
    (
        "gcp-principal:user:alice@example.com",
        "//privilegedaccessmanager.googleapis.com/projects/proj-a/locations/global/entitlements/break-glass",
        E.ASSUMES_ROLE,
        "ROLE_ASSUMES_ROLE",
    ),
    (
        "//privilegedaccessmanager.googleapis.com/projects/proj-a/locations/global/entitlements/break-glass",
        "//iam.googleapis.com/roles/owner",
        E.IAM_POLICY_ATTACHMENT,
        "ROLE_HAS_POLICY",
    ),
    (
        "//privilegedaccessmanager.googleapis.com/projects/proj-a/locations/global/entitlements/break-glass",
        "gcp-principal:group:sec@example.com",
        E.REFERENCES,
        "DEPENDS_ON",
    ),
    (
        "//iam.googleapis.com/projects/proj-a/oauthClients/oc",
        "//iam.googleapis.com/projects/proj-a/oauthClients/oc/credentials/c",
        E.CONTAINS,
        None,
    ),
    (
        "gcp-principal:user:bob@example.com",
        "//iam.googleapis.com/projects/proj-a/roles/deployer",
        E.IAM_POLICY_ATTACHMENT,
        "USER_HAS_POLICY",
    ),
    (
        "gcp-principal:group:readers@example.com",
        "//iam.googleapis.com/roles/storage.objectViewer",
        E.IAM_POLICY_ATTACHMENT,
        "GROUP_HAS_POLICY",
    ),
    (
        SA_ARN,
        "//iam.googleapis.com/roles/storage.objectViewer",
        E.IAM_POLICY_ATTACHMENT,
        "ROLE_HAS_POLICY",
    ),
    # CI/CD
    (
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/workerPools/wp",
        NET1,
        E.PEERING,
        "VPC_PEERED",
    ),
    (
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/connections/gh",
        "//secretmanager.googleapis.com/projects/proj-a/secrets/gh-token",
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/connections/gh",
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/connections/gh/repositories/app",
        E.CONTAINS,
        None,
    ),
    (
        "//developerconnect.googleapis.com/projects/proj-a/locations/us-central1/connections/dc",
        "//secretmanager.googleapis.com/projects/proj-a/secrets/gh-token",
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//developerconnect.googleapis.com/projects/proj-a/locations/us-central1/connections/dc",
        "//developerconnect.googleapis.com/projects/proj-a/locations/us-central1/connections/dc/gitRepositoryLinks/l",
        E.CONTAINS,
        None,
    ),
    (
        "//developerconnect.googleapis.com/projects/proj-a/locations/us-central1/insightsConfigs/ic",
        REPO,
        E.MONITORS,
        "MONITORED_BY",
    ),
    (
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/triggers/deploy",
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/connections/gh/repositories/app",
        E.REFERENCES,
        "READS_FROM",
    ),
    (
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/triggers/deploy",
        "//cloudbuild.googleapis.com/projects/proj-a/locations/us-central1/workerPools/wp",
        E.REFERENCES,
        "RUNS_ON",
    ),
]

# Config Connector label on a bucket in a project with one KCC-enabled cluster
BKT_KCC = R(
    SINK + "-kcc",
    "storage.googleapis.com/Bucket",
    {"name": "sink-bkt-kcc", "labels": {"managed-by-cnrm": "true"}},
)
CASES.append((CR, SINK + "-kcc", E.MANAGES, "OWNED_BY"))
CASES.remove((CR, BKT, E.MANAGES, "OWNED_BY"))

_SPECIAL = ("gcp-principal:", "serviceAccount:")


def _stubs() -> list[dict]:
    known = {r["name"] for r in RESOURCES} | {BKT_KCC["name"]}
    out = []
    for src, dst, *_ in CASES:
        for name in (src, dst):
            if name.startswith("//") and name not in known:
                known.add(name)
                out.append(R(name, "widgets.googleapis.com/Stub", {}))
    return out


@pytest.fixture(scope="module")
def parity():
    client = FakeAssetClient(resources=RESOURCES + [BKT_KCC] + _stubs(), iam=IAM)
    collector = GCPDeepInventoryCollector(PROJECT, credentials=None, client=client)
    assets, edges, linker = _collect(collector)
    return {"assets": assets, "edges": edges, "collector": collector}


@pytest.mark.parametrize(
    "src,dst,edge,relationship", CASES, ids=lambda v: str(v)[-60:] if isinstance(v, str) else None
)
def test_extractor_edge(parity, src, dst, edge, relationship):
    assets = parity["assets"]
    s, d = by_arn(assets, src), by_arn(assets, dst)
    assert has_edge(parity["edges"], s, d, edge, relationship), (src, dst, edge, relationship)


def test_every_new_catalog_type_has_an_extractor():
    deep = load_catalog("gcp_asset_types")["deep"]
    missing = sorted(t for t in deep if t not in EXTRACTORS)
    assert missing == []


def test_asset_types(parity):
    a = parity["assets"]
    assert by_arn(a, REPO + "/dockerImages/img@sha256:abc").asset_type == AssetType.CONTAINER_IMAGE
    assert by_arn(a, BASE).asset_type == AssetType.DATA_TABLE
    assert by_arn(a, f"{CRM}tagValues/2").asset_type == AssetType.TAG
    assert (
        by_arn(
            a, "//gkehub.googleapis.com/projects/proj-a/locations/global/memberships/m1"
        ).asset_type
        == AssetType.FLEET
    )
    assert (
        by_arn(
            a, "//cloudscheduler.googleapis.com/projects/proj-a/locations/us-central1/jobs/nightly"
        ).asset_type
        == AssetType.SCHEDULE
    )
    assert by_arn(a, AI + "reasoningEngines/agent").asset_type == AssetType.AI_AGENT
    assert by_arn(a, IDS).asset_type == AssetType.THREAT_DETECTOR
    assert by_arn(a, BDR + "backupVaults/v").asset_type == AssetType.BACKUP_VAULT
    assert (
        by_arn(
            a, "//assuredworkloads.googleapis.com/organizations/999/locations/us/workloads/w"
        ).asset_type
        == AssetType.LANDING_ZONE
    )


def test_metadata_only_extractors(parity):
    a = parity["assets"]
    assert (
        by_arn(a, NSEC + "projects/proj-a/locations/global/addressGroups/ag").metadata["item_count"]
        == 1
    )
    assert by_arn(a, NSVC + "meshes/mesh").metadata["interception_port"] == 15001
    assert by_arn(a, NSVC + "serviceLbPolicies/lbp").metadata["load_balancing_algorithm"]
    assert by_arn(a, CM + "trustConfigs/tc").metadata["trust_store_count"] == 1
    assert by_arn(a, POOL).metadata["tier"] == "ENTERPRISE"
    assert by_arn(a, CM + "dnsAuthorizations/da").metadata["domain"] == "api.example.com"
    assert (
        by_arn(
            a, "//binaryauthorization.googleapis.com/projects/proj-a/platforms/gke/policies/pp"
        ).metadata["check_set_count"]
        == 1
    )
    assert (
        by_arn(a, "//pubsub.googleapis.com/projects/proj-a/schemas/orders").metadata["schema_type"]
        == "AVRO"
    )
    assert by_arn(
        a, "//eventarc.googleapis.com/projects/proj-a/locations/us-central1/messageBuses/bus"
    )
    assert by_arn(
        a, "//datacatalog.googleapis.com/projects/proj-a/locations/us/taxonomies/tx"
    ).metadata["activated_policy_types"]
    assert by_arn(
        a, "//modelarmor.googleapis.com/projects/proj-a/locations/us-central1/templates/guard"
    ).metadata["filters"]
    assert (
        by_arn(a, "//dialogflow.googleapis.com/projects/proj-a/knowledgeBases/kbase").metadata[
            "language"
        ]
        == "en"
    )
    assert by_arn(a, AI + "featurestores/fs").metadata["online_serving_nodes"] == 1
    assert (
        by_arn(
            a, "//dlp.googleapis.com/projects/proj-a/locations/global/inspectTemplates/it"
        ).metadata["info_type_count"]
        == 1
    )
    assert by_arn(a, "//iam.googleapis.com/projects/proj-a/oauthClients/oc").metadata["client_type"]
    assert (
        by_arn(
            a, f"//iam.googleapis.com/projects/{NUMBER}/locations/global/workloadIdentityPools/gh"
        ).metadata["mode"]
        == "FEDERATION_ONLY"
    )
    assert (
        by_arn(a, "//cloudkms.googleapis.com/projects/proj-a/locations/us/keyRings/ring").metadata[
            "key_ring"
        ]
        == "ring"
    )
    assert by_arn(a, "//firestore.googleapis.com/projects/proj-a/databases/(default)").metadata[
        "database_type"
    ]
    assert by_arn(a, NETAPP + "backupVaults/nv")
    assert by_arn(a, CR + "/k8s/clusterroles/admin").metadata["reads_secrets"] is True
    assert (
        by_arn(
            a, "//parametermanager.googleapis.com/projects/proj-a/locations/global/parameters/cfg"
        ).metadata["format"]
        == "YAML"
    )
    role = by_arn(a, "//iam.googleapis.com/projects/proj-a/roles/deployer")
    assert role.metadata["included_permissions"] == ["run.services.update"]
    assert role.metadata["predefined"] is False


def test_exposure(parity):
    a = parity["assets"]
    assert by_arn(a, NSVC + "edgeCacheServices/cdn").is_internet_exposed
    assert by_arn(a, AI + "indexEndpoints/ie").is_internet_exposed
    assert by_arn(a, AI + "featureOnlineStores/fos").is_internet_exposed
    assert by_arn(
        a, "//datafusion.googleapis.com/projects/proj-a/locations/us-central1/instances/df"
    ).is_internet_exposed


def test_secrets_are_scrubbed(parity):
    for a in parity["assets"]:
        blob = repr(a.metadata) + repr(a.raw_data)
        assert "tok-secret" not in blob
        assert "hunter2" not in blob


def test_tag_bindings_are_folded(parity):
    a = parity["assets"]
    assert not any(x.arn == f"{CRM}tagBindings/x" for x in a)
    assert by_arn(a, BKT).metadata["resource_manager_tags"] == ["999/env/prod"]


def test_api_gateway_authorizer(parity):
    a = parity["assets"]
    config = "//apigateway.googleapis.com/projects/proj-a/locations/global/apis/orders/configs/v1"
    auth = by_arn(a, config + "/authorizers/svc_jwt")
    assert auth.asset_type == AssetType.AUTHORIZER
    assert auth.metadata["audiences"] == ["orders-api"]
    edges = parity["edges"]
    assert has_edge(edges, by_arn(a, config), auth, E.CONTAINS)
    assert has_edge(edges, auth, by_arn(a, SA_ARN), E.REFERENCES, "DEPENDS_ON")


def test_cross_cloud_relations_are_declared():
    conn = extract(
        GCPContext(
            name="//bigqueryconnection.googleapis.com/projects/p/locations/aws-us-east-1/connections/omni",
            asset_type="bigqueryconnection.googleapis.com/Connection",
            data={"aws": {"accessRole": {"iamRoleId": "arn:aws:iam::123456789012:role/omni"}}},
            project_id="p",
        )
    )
    assert {
        "target": "arn:aws:iam::123456789012:role/omni",
        "edge": "ASSUMES_ROLE",
        "relationship": "CROSS_ACCOUNT_TRUST",
        "description": "BigQuery Omni assumes the AWS role",
    } in conn.relations
    job = extract(
        GCPContext(
            name="//storagetransfer.googleapis.com/transferJobs/9",
            asset_type="storagetransfer.googleapis.com/TransferJob",
            data={
                "transferSpec": {
                    "awsS3DataSource": {
                        "bucketName": "src",
                        "roleArn": "arn:aws:iam::123456789012:role/sts",
                    },
                    "gcsDataSink": {"bucketName": "dst"},
                }
            },
            project_id="p",
        )
    )
    targets = {(r["target"], r.get("relationship")) for r in job.relations}
    assert ("arn:aws:s3:::src", "READS_FROM") in targets
    assert ("arn:aws:iam::123456789012:role/sts", "CROSS_ACCOUNT_TRUST") in targets


def test_parsers():
    assert sql_table_refs("select * from `p.d.t` join d.u using (x)", "dp") == [
        "//bigquery.googleapis.com/projects/p/datasets/d/tables/t",
        "//bigquery.googleapis.com/projects/dp/datasets/d/tables/u",
    ]
    assert v1_member("principal://goog/subject/a@x.com") == "user:a@x.com"
    assert v1_member("principalSet://goog/group/g@x.com") == "group:g@x.com"
    assert (
        v1_member(
            "principal://iam.googleapis.com/projects/-/serviceAccounts/s@p.iam.gserviceaccount.com"
        )
        == "serviceAccount:s@p.iam.gserviceaccount.com"
    )
    assert v1_member("principalSet://goog/public:all") == "allUsers"
    assert (
        deny_attachment_point(
            "//iam.googleapis.com/policies/cloudresourcemanager.googleapis.com%2Fprojects%2F1/denypolicies/x"
        )
        == "//cloudresourcemanager.googleapis.com/projects/1"
    )
    assert filter_targets(
        'resource.type="gce_instance" AND resource.labels.instance_id="7" AND resource.labels.zone="z-1"',
        "p",
    ) == ["//compute.googleapis.com/projects/p/zones/z-1/instances/7"]
    assert filter_targets(
        'resource.type = "cloudsql_database" AND resource.label.database_id = "p:db"', "p"
    ) == ["//cloudsql.googleapis.com/projects/p/instances/db"]
    calls = workflow_calls(WORKFLOW_SOURCE)
    assert (TOPIC, E.REFERENCES, "WRITES_TO") in calls


def test_hierarchy_access_levels():
    from cloudg.inventory.gcp_hierarchy import discover_gcp_hierarchy
    from cloudg.inventory.linker import RelationshipLinker

    level = {
        "name": "//accesscontextmanager.googleapis.com/accessPolicies/1/accessLevels/corp",
        "access_level": {
            "name": "accessPolicies/1/accessLevels/corp",
            "title": "corp network",
            "basic": {"conditions": [{"ip_subnetworks": ["203.0.113.0/24"], "regions": ["CH"]}]},
        },
    }
    perimeter = {
        "name": "//accesscontextmanager.googleapis.com/accessPolicies/1/servicePerimeters/p1",
        "service_perimeter": {
            "name": "accessPolicies/1/servicePerimeters/p1",
            "status": {
                "resources": [f"projects/{NUMBER}"],
                "access_levels": ["accessPolicies/1/accessLevels/corp"],
            },
        },
    }
    org = R(
        ORG, "cloudresourcemanager.googleapis.com/Organization", {}, ancestors=["organizations/999"]
    )
    client = FakeAssetClient(resources=[org, PROJECT_ASSET], access=[level, perimeter])
    assets = discover_gcp_hierarchy(None, "999", client=client)
    edges = RelationshipLinker(assets).link()
    lvl = by_arn(assets, level["name"])
    assert lvl.asset_type == AssetType.GUARDRAIL
    assert lvl.metadata["ip_subnetworks"] == ["203.0.113.0/24"]
    assert has_edge(edges, by_arn(assets, perimeter["name"]), lvl, E.REFERENCES, "DEPENDS_ON")
