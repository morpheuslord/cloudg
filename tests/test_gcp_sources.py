"""API-backed GCP sources, per-family coverage, service filtering and the REST client.

Every REST call is served by :class:`tests.gcp_fakes.FakeSession`; nothing
touches the network.
"""

from __future__ import annotations

import pytest

from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.exceptions import CredentialError
from cloudg.inventory.gcp_deep import GCPDeepInventoryCollector, deep_options_from_config
from cloudg.inventory.gcp_sources import SOURCES, GCPApiError
from cloudg.inventory.gcp_tasks import families, gcp_family, is_selected, type_selected
from cloudg.schema.models import AssetType, EdgeType
from tests.gcp_fakes import FakeResponse, api_error, denied, disabled, rest_client
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
    run,
)

E = EdgeType
ORG = f"{CRM}organizations/999"
PROJ = f"{CRM}projects/{NUMBER}"
NET1 = C + "global/networks/net1"
BKT = "//storage.googleapis.com/media-bkt"
TOPIC = "//pubsub.googleapis.com/projects/proj-a/topics/jobs"
RUN = "//run.googleapis.com/projects/proj-a/locations/us-central1/services/orders"
RUN_URI = "https://orders-abc-uc.a.run.app"
VM = C + "zones/us-central1-a/instances/vm1"
REPO = "//artifactregistry.googleapis.com/projects/proj-a/locations/us/repositories/repo"
IMAGE = REPO + "/dockerImages/img@sha256:abc"
SA_ARN = f"//iam.googleapis.com/projects/{PROJECT}/serviceAccounts/{APP_SA}"
ZONE = "//dns.googleapis.com/projects/proj-a/managedZones/example"
FIRESTORE = "//firestore.googleapis.com/projects/proj-a/databases/(default)"
APIGEE = "//apigee.googleapis.com/organizations/proj-a"
IM = "//config.googleapis.com/projects/proj-a/locations/us-central1/deployments/im"


def R(name, asset_type, data=None, location="", ancestors=None):
    return res(name, asset_type, data or {}, location=location, ancestors=ancestors)


RESOURCES = [
    PROJECT_ASSET,
    R(
        ORG,
        "cloudresourcemanager.googleapis.com/Organization",
        {"owner": {"directoryCustomerId": "C0abc"}},
        ancestors=["organizations/999"],
    ),
    R(NET1, "compute.googleapis.com/Network", {"name": "net1"}),
    R(BKT, "storage.googleapis.com/Bucket", {"name": "media-bkt", "labels": {"goog-dm": "web"}}),
    R(TOPIC, "pubsub.googleapis.com/Topic", {}),
    R(RUN, "run.googleapis.com/Service", {"template": {}, "uri": RUN_URI}, "us-central1"),
    R(SA_ARN, "iam.googleapis.com/ServiceAccount", {"email": APP_SA, "projectId": PROJECT}),
    R(
        VM,
        "compute.googleapis.com/Instance",
        {"name": "vm1", "id": "4242", "labels": {"env": "prod"}},
        "us-central1-a",
    ),
    R(
        C + "regions/us-central1/addresses/web",
        "compute.googleapis.com/Address",
        {"address": "34.1.2.3", "addressType": "EXTERNAL"},
        "us-central1",
    ),
    R(REPO, "artifactregistry.googleapis.com/Repository", {"format": "DOCKER"}, "us"),
    R(
        IMAGE,
        "artifactregistry.googleapis.com/DockerImage",
        {"uri": "us-docker.pkg.dev/proj-a/repo/img@sha256:abc"},
        "us",
    ),
    R(
        ZONE,
        "dns.googleapis.com/ManagedZone",
        {"name": "example", "dnsName": "example.com.", "visibility": "public"},
    ),
    R(FIRESTORE, "firestore.googleapis.com/Database", {"type": "FIRESTORE_NATIVE"}, "nam5"),
    R(APIGEE, "apigee.googleapis.com/Organization", {"projectId": PROJECT}),
    R(APIGEE + "/environments/prod", "apigee.googleapis.com/Environment", {}),
    R(APIGEE + "/apis/orders", "apigee.googleapis.com/ApiProxy", {}),
    R(
        IM,
        "config.googleapis.com/Deployment",
        {"latestRevision": "projects/proj-a/locations/us-central1/deployments/im/revisions/r-1"},
        "us-central1",
    ),
    R(
        "//securitycenter.googleapis.com/organizations/999/notificationConfigs/n",
        "securitycenter.googleapis.com/NotificationConfig",
        {"pubsubTopic": "projects/proj-a/topics/jobs"},
        ancestors=["organizations/999"],
    ),
]

IAM = [
    {
        "resource": BKT,
        "policy": {"bindings": [{"role": "roles/viewer", "members": ["group:devs@example.com"]}]},
    }
]

SCC = "https://securitycenter.googleapis.com"
SCCM = "https://securitycentermanagement.googleapis.com/v1"
ATT = "cloudresourcemanager.googleapis.com%2Fprojects%2Fproj-a"

ROUTES = {
    # Cloud DNS
    "https://dns.googleapis.com/dns/v1/projects/proj-a/managedZones/example/rrsets": [
        {
            "rrsets": [
                {"name": "api.example.com.", "type": "A", "ttl": 300, "rrdatas": ["34.1.2.3"]}
            ],
            "nextPageToken": "p2",
        },
        {
            "rrsets": [
                {
                    "name": "app.example.com.",
                    "type": "CNAME",
                    "rrdatas": ["orders-abc-uc.a.run.app."],
                }
            ]
        },
    ],
    # Security Command Center: org activated, project not
    f"{SCCM}/organizations/999/locations/global/securityCenterServices": {
        "securityCenterServices": [
            {
                "name": "organizations/999/locations/global/securityCenterServices/event-threat-detection",
                "effectiveEnablementState": "ENABLED",
            },
            {
                "name": "organizations/999/locations/global/securityCenterServices/container-threat-detection",
                "effectiveEnablementState": "DISABLED",
            },
        ]
    },
    f"{SCC}/v1beta2/organizations/999/subscription": {
        "name": "organizations/999/subscription",
        "tier": "PREMIUM",
    },
    f"{SCC}/v1/organizations/999/sources": {
        "sources": [
            {"name": "organizations/999/sources/42", "displayName": "Security Health Analytics"}
        ]
    },
    f"{SCC}/v1/organizations/999/notificationConfigs": {
        "notificationConfigs": [
            {
                "name": "organizations/999/notificationConfigs/n",
                "pubsubTopic": "projects/proj-a/topics/jobs",
            }
        ]
    },
    f"{SCCM}/projects/proj-a/locations/global/securityCenterServices": disabled(
        "securitycentermanagement.googleapis.com"
    ),
    # Cloud Identity
    "https://cloudidentity.googleapis.com/v1/groups": {
        "groups": [
            {
                "name": "groups/g1",
                "groupKey": {"id": "devs@example.com"},
                "labels": {"cloudidentity.googleapis.com/groups.security": ""},
            }
        ]
    },
    "https://cloudidentity.googleapis.com/v1/groups/g1/memberships": {
        "memberships": [
            {
                "preferredMemberKey": {"id": "alice@example.com"},
                "type": "USER",
                "roles": [{"name": "MEMBER"}],
            },
            {
                "preferredMemberKey": {"id": APP_SA},
                "type": "SERVICE_ACCOUNT",
                "roles": [{"name": "MEMBER"}],
            },
        ]
    },
    # IAM deny
    f"https://iam.googleapis.com/v2/policies/{ATT}/denypolicies": {
        "policies": [{"name": f"policies/{ATT}/denypolicies/rest-deny"}]
    },
    f"https://iam.googleapis.com/v2/policies/{ATT}/denypolicies/rest-deny": {
        "name": f"policies/{ATT}/denypolicies/rest-deny",
        "rules": [
            {
                "denyRule": {
                    "deniedPrincipals": ["principal://goog/subject/mallory@example.com"],
                    "deniedPermissions": ["storage.buckets.delete"],
                }
            }
        ],
    },
    # Principal Access Boundary
    "https://iam.googleapis.com/v3/organizations/999/locations/global/principalAccessBoundaryPolicies": {
        "principalAccessBoundaryPolicies": [
            {
                "name": "organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
                "details": {"rules": [{"resources": [PROJ], "effect": "ALLOW"}]},
            }
        ]
    },
    "https://iam.googleapis.com/v3/projects/proj-a/locations/global/policyBindings": {
        "policyBindings": [
            {
                "name": "projects/proj-a/locations/global/policyBindings/b",
                "target": {"principalSet": PROJ},
                "policy": "organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
                "policyKind": "PRINCIPAL_ACCESS_BOUNDARY",
            }
        ]
    },
    # PAM
    "https://privilegedaccessmanager.googleapis.com/v1/projects/proj-a/locations/global/entitlements": {
        "entitlements": [
            {
                "name": "projects/proj-a/locations/global/entitlements/oncall",
                "eligibleUsers": [{"principals": ["group:devs@example.com"]}],
                "privilegedAccess": {
                    "gcpIamAccess": {
                        "resource": f"{CRM}projects/proj-a",
                        "resourceType": "cloudresourcemanager.googleapis.com/Project",
                        "roleBindings": [{"role": "roles/compute.admin"}],
                    }
                },
            }
        ]
    },
    # Predefined role permissions
    "https://iam.googleapis.com/v1/roles/viewer": {
        "name": "roles/viewer",
        "title": "Viewer",
        "includedPermissions": ["storage.buckets.get", "storage.objects.list"],
    },
    # Audit configs: org on, project off, folder denied
    "https://cloudresourcemanager.googleapis.com/v3/organizations/999:getIamPolicy": {
        "auditConfigs": [
            {
                "service": "allServices",
                "auditLogConfigs": [
                    {"logType": "DATA_READ"},
                    {"logType": "DATA_WRITE", "exemptedMembers": ["user:svc@example.com"]},
                ],
            }
        ]
    },
    "https://cloudresourcemanager.googleapis.com/v3/projects/proj-a:getIamPolicy": {"bindings": []},
    "https://cloudresourcemanager.googleapis.com/v3/folders/555:getIamPolicy": denied(),
    # Monitoring
    "https://monitoring.googleapis.com/v3/projects/proj-a/alertPolicies": {
        "alertPolicies": [
            {
                "name": "projects/proj-a/alertPolicies/7",
                "conditions": [
                    {
                        "conditionThreshold": {
                            "filter": 'resource.type = "gce_instance" AND resource.labels.instance_id = "4242" AND resource.labels.zone = "us-central1-a"'
                        }
                    }
                ],
                "notificationChannels": ["projects/proj-a/notificationChannels/3"],
            }
        ]
    },
    "https://monitoring.googleapis.com/v3/projects/proj-a/notificationChannels": {
        "notificationChannels": [
            {
                "name": "projects/proj-a/notificationChannels/3",
                "type": "slack",
                "labels": {"channel_name": "#ops", "auth_token": "xoxb-secret"},
            }
        ]
    },
    "https://monitoring.googleapis.com/v1/locations/global/metricsScopes/proj-a": {
        "monitoredProjects": [{"name": "locations/global/metricsScopes/111/projects/222"}]
    },
    # OS Config
    "https://osconfig.googleapis.com/v1/projects/proj-a/patchDeployments": {
        "patchDeployments": [
            {
                "name": "projects/proj-a/patchDeployments/pd",
                "instanceFilter": {"instances": ["zones/us-central1-a/instances/vm1"]},
            }
        ]
    },
    "https://osconfig.googleapis.com/v1/projects/proj-a/locations/us-central1-a/osPolicyAssignments": {
        "osPolicyAssignments": [
            {
                "name": "projects/proj-a/locations/us-central1-a/osPolicyAssignments/opa",
                "instanceFilter": {"inclusionLabels": [{"labels": {"env": "prod"}}]},
            }
        ]
    },
    "https://osconfig.googleapis.com/v1/projects/proj-a/locations/us-central1-a/instances/-/vulnerabilityReports": {
        "vulnerabilityReports": [
            {
                "name": "projects/111/locations/us-central1-a/instances/4242/vulnerabilityReport",
                "vulnerabilities": [{"details": {"cve": "CVE-1", "severity": "CRITICAL"}}],
            }
        ]
    },
    # Artifact Analysis
    "https://serviceusage.googleapis.com/v1/projects/proj-a/services/containerscanning.googleapis.com": {
        "state": "ENABLED"
    },
    "https://containeranalysis.googleapis.com/v1/projects/proj-a/occurrences": {
        "occurrences": [
            {
                "resourceUri": "https://us-docker.pkg.dev/proj-a/repo/img@sha256:abc",
                "noteName": "projects/goog-vulnz/notes/CVE-2026-1",
                "vulnerability": {"effectiveSeverity": "HIGH", "fixAvailable": True},
            },
            {
                "resourceUri": "https://us-docker.pkg.dev/proj-a/repo/img@sha256:abc",
                "noteName": "projects/goog-vulnz/notes/CVE-2026-2",
                "vulnerability": {"effectiveSeverity": "LOW"},
            },
        ]
    },
    # Backup and DR: vaults answer, the rest are not enabled
    "https://backupdr.googleapis.com/v1/projects/proj-a/locations/-/backupVaults": {
        "backupVaults": [
            {
                "name": "projects/proj-a/locations/us-central1/backupVaults/rest-vault",
                "serviceAccount": "v@gcp-sa-backupdr.iam.gserviceaccount.com",
            }
        ]
    },
    "https://backupdr.googleapis.com/v1/projects/proj-a/locations/-/backupPlans": {
        "backupPlans": [
            {
                "name": "projects/proj-a/locations/us-central1/backupPlans/rest-plan",
                "backupVault": "projects/proj-a/locations/us-central1/backupVaults/rest-vault",
            }
        ]
    },
    "https://backupdr.googleapis.com/v1/projects/proj-a/locations/-/backupPlanAssociations": {
        "backupPlanAssociations": [
            {
                "name": "projects/proj-a/locations/us-central1/backupPlanAssociations/a",
                "resource": "projects/proj-a/zones/us-central1-a/instances/vm1",
                "resourceType": "compute.googleapis.com/Instance",
                "backupPlan": "projects/proj-a/locations/us-central1/backupPlans/rest-plan",
            }
        ]
    },
    # Firestore
    "https://firestore.googleapis.com/v1/projects/proj-a/databases/(default)/backupSchedules": {
        "backupSchedules": [
            {
                "name": "projects/proj-a/databases/(default)/backupSchedules/daily",
                "retention": "604800s",
                "dailyRecurrence": {},
            }
        ]
    },
    # Cloud Scheduler
    "https://cloudscheduler.googleapis.com/v1/projects/proj-a/locations/us-central1/jobs": {
        "jobs": [
            {
                "name": "projects/proj-a/locations/us-central1/jobs/kick",
                "schedule": "*/5 * * * *",
                "pubsubTarget": {"topicName": "projects/proj-a/topics/jobs"},
            }
        ]
    },
    # Apigee
    "https://apigee.googleapis.com/v1/organizations/proj-a/environments": FakeResponse(
        200, ["prod"]
    ),
    "https://apigee.googleapis.com/v1/organizations/proj-a/environments/prod/targetservers": FakeResponse(
        200, ["orders-backend"]
    ),
    "https://apigee.googleapis.com/v1/organizations/proj-a/environments/prod/targetservers/orders-backend": {
        "name": "orders-backend",
        "host": "orders-abc-uc.a.run.app",
        "port": 443,
        "sSLInfo": {"enabled": True},
    },
    "https://apigee.googleapis.com/v1/organizations/proj-a/deployments": {
        "deployments": [{"environment": "prod", "apiProxy": "orders", "revision": "3"}]
    },
    # Infrastructure Manager
    "https://config.googleapis.com/v1/projects/proj-a/locations/us-central1/deployments/im/revisions/r-1/resources": {
        "resources": [
            {"name": "r", "caiAssets": {"pubsub.googleapis.com/Topic": {"fullResourceName": TOPIC}}}
        ]
    },
    # Deployment Manager
    "https://deploymentmanager.googleapis.com/deploymentmanager/v2/projects/proj-a/global/deployments": {
        "deployments": [{"name": "web", "manifest": "manifest-1"}]
    },
    "https://deploymentmanager.googleapis.com/deploymentmanager/v2/projects/proj-a/global/deployments/web/resources": {
        "resources": [
            {"name": "net1", "type": "compute.v1.network", "url": SL + "global/networks/net1"}
        ]
    },
    # IAM recommender
    "https://recommender.googleapis.com/v1/projects/proj-a/locations/global/recommenders/google.iam.policy.Recommender/recommendations": {
        "recommendations": [
            {
                "name": "r1",
                "description": "Replace a role",
                "priority": "P2",
                "content": {
                    "operationGroups": [
                        {
                            "operations": [
                                {
                                    "action": "remove",
                                    "resource": BKT,
                                    "pathFilters": {
                                        "/iamPolicy/bindings/*/role": "roles/viewer",
                                        "/iamPolicy/bindings/*/members/*": "group:devs@example.com",
                                    },
                                }
                            ]
                        }
                    ]
                },
            }
        ]
    },
}


@pytest.fixture(scope="module")
def sourced():
    rest, session = rest_client(ROUTES)
    cov = CollectionCoverage(provider="gcp")
    client = FakeAssetClient(resources=RESOURCES, iam=IAM)
    collector = GCPDeepInventoryCollector(PROJECT, client=client, rest_client=rest, coverage=cov)
    assets, edges, linker = _collect(collector)
    status = {s.service: s for s in cov.services}
    return {
        "assets": assets,
        "edges": edges,
        "status": status,
        "session": session,
        "linker": linker,
    }


def edge(sourced, src, dst, et, rel=None):
    a = sourced["assets"]
    return has_edge(sourced["edges"], by_arn(a, src), by_arn(a, dst), et, rel)


class TestSources:
    def test_dns_records(self, sourced):
        a = sourced["assets"]
        rec_a = (
            "//dns.googleapis.com/projects/proj-a/managedZones/example/rrsets/api.example.com./A"
        )
        rec_c = "//dns.googleapis.com/projects/proj-a/managedZones/example/rrsets/app.example.com./CNAME"
        assert by_arn(a, rec_a).asset_type == AssetType.DNS_RECORD
        assert edge(
            sourced, rec_a, C + "regions/us-central1/addresses/web", E.ROUTE, "DNS_RESOLVED"
        )
        assert edge(sourced, rec_c, RUN, E.ROUTE, "DNS_RESOLVED")
        assert edge(sourced, ZONE, rec_a, E.CONTAINS)

    def test_scc(self, sourced):
        a = sourced["assets"]
        hub = by_arn(a, "//securitycenter.googleapis.com/organizations/999/securityCenter")
        assert hub.asset_type == AssetType.SECURITY_HUB and hub.metadata["tier"] == "PREMIUM"
        assert has_edge(sourced["edges"], hub, by_arn(a, ORG), E.MONITORS, "MONITORED_BY")
        etd = by_arn(
            a,
            "//securitycentermanagement.googleapis.com/organizations/999/locations/global/securityCenterServices/event-threat-detection",
        )
        assert etd.asset_type == AssetType.THREAT_DETECTOR and etd.metadata["enabled"]
        assert has_edge(sourced["edges"], etd, by_arn(a, ORG), E.MONITORS, "MONITORED_BY")
        ctd = by_arn(
            a,
            "//securitycentermanagement.googleapis.com/organizations/999/locations/global/securityCenterServices/container-threat-detection",
        )
        assert ctd.name.endswith("(not enabled)") and not ctd.metadata["enabled"]
        source = by_arn(a, "//securitycenter.googleapis.com/organizations/999/sources/42")
        assert has_edge(sourced["edges"], source, hub, E.INVOKES, "STREAMS_TO")
        # The listed notification config is not duplicated and depends on SCC
        notes = [
            x
            for x in a
            if x.arn == "//securitycenter.googleapis.com/organizations/999/notificationConfigs/n"
        ]
        assert len(notes) == 1
        assert has_edge(sourced["edges"], notes[0], hub, E.REFERENCES, "DEPENDS_ON")

    def test_scc_not_enabled_placeholders(self, sourced):
        a = sourced["assets"]
        scc = by_arn(a, "cloudg:gcp:scc:projects/proj-a:not-enabled")
        assert scc.name == "Security Command Center (not enabled)"
        assert scc.metadata["enabled"] is False
        assert "gcp-security:scc:projects/proj-a" in scc.metadata["aliases"]
        sha = by_arn(a, "cloudg:gcp:security-health-analytics:projects/proj-a:not-enabled")
        assert sha.asset_type == AssetType.CONFIG_RECORDER
        assert (
            by_arn(a, "cloudg:gcp:web-security-scanner:projects/proj-a:not-enabled").asset_type
            == AssetType.VULNERABILITY_SCANNER
        )

    def test_cloud_identity_groups(self, sourced):
        a = sourced["assets"]
        group = by_arn(a, "//cloudidentity.googleapis.com/groups/g1")
        assert group.asset_type == AssetType.IDENTITY_GROUP and group.name == "devs@example.com"
        assert group.metadata["security_group"] is True
        assert has_edge(
            sourced["edges"], group, by_arn(a, "gcp-principal:user:alice@example.com"), E.CONTAINS
        )
        assert has_edge(sourced["edges"], group, by_arn(a, SA_ARN), E.CONTAINS)
        # The IAM binding of group:devs lands on the Cloud Identity group, no placeholder
        assert not any(x.arn == "gcp-principal:group:devs@example.com" for x in a)
        assert has_edge(
            sourced["edges"], group, by_arn(a, BKT), E.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION"
        )
        assert has_edge(
            sourced["edges"],
            group,
            by_arn(a, "//iam.googleapis.com/roles/viewer"),
            E.IAM_POLICY_ATTACHMENT,
            "GROUP_HAS_POLICY",
        )

    def test_iam_deny(self, sourced):
        a = sourced["assets"]
        pol = by_arn(a, f"//iam.googleapis.com/policies/{ATT}/denypolicies/rest-deny")
        assert pol.asset_type == AssetType.IAM_POLICY
        assert has_edge(sourced["edges"], pol, by_arn(a, PROJ), E.GOVERNS, "POLICY_DENIES_ACTION")
        assert has_edge(
            sourced["edges"],
            pol,
            by_arn(a, "gcp-principal:user:mallory@example.com"),
            E.GOVERNS,
            "POLICY_DENIES_ACTION",
        )

    def test_principal_access_boundary(self, sourced):
        a = sourced["assets"]
        pab = by_arn(
            a,
            "//iam.googleapis.com/organizations/999/locations/global/principalAccessBoundaryPolicies/pab",
        )
        assert has_edge(
            sourced["edges"], pab, by_arn(a, PROJ), E.GOVERNS, "PERMISSION_BOUNDARY_LIMITS"
        )
        assert has_edge(
            sourced["edges"], by_arn(a, PROJ), pab, E.REFERENCES, "PERMISSION_BOUNDARY_LIMITS"
        )

    def test_pam(self, sourced):
        a = sourced["assets"]
        ent = by_arn(
            a,
            "//privilegedaccessmanager.googleapis.com/projects/proj-a/locations/global/entitlements/oncall",
        )
        assert ent.asset_type == AssetType.PERMISSION_SET
        group = by_arn(a, "//cloudidentity.googleapis.com/groups/g1")
        assert has_edge(sourced["edges"], group, ent, E.ASSUMES_ROLE, "ROLE_ASSUMES_ROLE")
        assert has_edge(
            sourced["edges"], ent, by_arn(a, PROJ), E.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION"
        )
        assert has_edge(
            sourced["edges"],
            ent,
            by_arn(a, "//iam.googleapis.com/roles/compute.admin"),
            E.IAM_POLICY_ATTACHMENT,
            "ROLE_HAS_POLICY",
        )

    def test_predefined_roles(self, sourced):
        role = by_arn(sourced["assets"], "//iam.googleapis.com/roles/viewer")
        assert role.asset_type == AssetType.IAM_ROLE and role.account_id is None
        assert role.metadata["included_permissions"] == [
            "storage.buckets.get",
            "storage.objects.list",
        ]
        assert role.metadata["permissions_expanded"] is True

    def test_audit_configs(self, sourced):
        a = sourced["assets"]
        org_cfg = by_arn(a, "//logging.googleapis.com/organizations/999/auditConfig")
        assert org_cfg.asset_type == AssetType.CLOUDTRAIL
        assert org_cfg.metadata["all_services"] is True
        assert org_cfg.metadata["exempted_members"] == ["user:svc@example.com"]
        assert has_edge(sourced["edges"], org_cfg, by_arn(a, ORG), E.MONITORS, "MONITORED_BY")
        off = by_arn(a, "cloudg:gcp:audit-logs:projects/proj-a:not-enabled")
        assert off.name.endswith("(not enabled)") and off.metadata["enabled"] is False
        assert by_arn(a, ORG).metadata["data_access_audit_logs"] is True
        assert sourced["status"]["gcp_audit_configs"].status == ServiceStatus.PARTIAL

    def test_monitoring(self, sourced):
        a = sourced["assets"]
        policy = "//monitoring.googleapis.com/projects/proj-a/alertPolicies/7"
        channel = "//monitoring.googleapis.com/projects/proj-a/notificationChannels/3"
        assert edge(sourced, policy, VM, E.MONITORS, "MONITORED_BY")
        assert edge(sourced, policy, channel, E.INVOKES, "INVOKES")
        assert "xoxb-secret" not in repr(by_arn(a, channel).raw_data)
        other = next(x for x in sourced["linker"].external_assets if x.account_id == "222")
        assert has_edge(sourced["edges"], by_arn(a, PROJ), other, E.MONITORS, "MONITORED_BY")

    def test_os_config(self, sourced):
        assert edge(
            sourced,
            "//osconfig.googleapis.com/projects/proj-a/patchDeployments/pd",
            VM,
            E.MANAGES,
            "SCHEDULED_BY",
        )
        assert edge(
            sourced,
            "//osconfig.googleapis.com/projects/proj-a/locations/us-central1-a/osPolicyAssignments/opa",
            VM,
            E.MANAGES,
            "SCHEDULED_BY",
        )
        assert edge(
            sourced,
            "//osconfig.googleapis.com/projects/111/locations/us-central1-a/instances/4242/vulnerabilityReport",
            VM,
            E.MONITORS,
            "MONITORED_BY",
        )

    def test_artifact_analysis(self, sourced):
        a = sourced["assets"]
        summary = by_arn(
            a, "//containeranalysis.googleapis.com/projects/proj-a/vulnerabilitySummary"
        )
        assert summary.asset_type == AssetType.VULNERABILITY_SCANNER
        assert has_edge(sourced["edges"], summary, by_arn(a, IMAGE), E.MONITORS, "MONITORED_BY")
        assert by_arn(a, IMAGE).metadata["vulnerabilities"] == {"HIGH": 1, "LOW": 1}

    def test_backup_dr(self, sourced):
        vault = "//backupdr.googleapis.com/projects/proj-a/locations/us-central1/backupVaults/rest-vault"
        plan = (
            "//backupdr.googleapis.com/projects/proj-a/locations/us-central1/backupPlans/rest-plan"
        )
        assert edge(sourced, plan, vault, E.REFERENCES, "BACKUP_TO")
        assert edge(
            sourced,
            "//backupdr.googleapis.com/projects/proj-a/locations/us-central1/backupPlanAssociations/a",
            VM,
            E.MANAGES,
            "BACKUP_TO",
        )

    def test_firestore_backup_schedule(self, sourced):
        assert edge(
            sourced, FIRESTORE + "/backupSchedules/daily", FIRESTORE, E.MANAGES, "BACKUP_TO"
        )

    def test_cloud_scheduler(self, sourced):
        job = "//cloudscheduler.googleapis.com/projects/proj-a/locations/us-central1/jobs/kick"
        assert by_arn(sourced["assets"], job).asset_type == AssetType.SCHEDULE
        assert edge(sourced, job, TOPIC, E.INVOKES, "SCHEDULED_BY")

    def test_apigee(self, sourced):
        ts = APIGEE + "/environments/prod/targetservers/orders-backend"
        assert edge(sourced, ts, RUN, E.ROUTE, "SERVES_TRAFFIC_TO")
        assert edge(sourced, APIGEE + "/environments/prod", ts, E.CONTAINS)
        assert edge(sourced, APIGEE + "/apis/orders", APIGEE + "/environments/prod", E.ATTACHED_TO)

    def test_infra_manager(self, sourced):
        assert edge(sourced, IM, TOPIC, E.MANAGES, "OWNED_BY")

    def test_deployment_manager(self, sourced):
        dep = "//deploymentmanager.googleapis.com/projects/proj-a/global/deployments/web"
        assert by_arn(sourced["assets"], dep).asset_type == AssetType.IAC_STACK
        assert edge(sourced, dep, NET1, E.MANAGES, "OWNED_BY")
        assert edge(sourced, dep, BKT, E.MANAGES, "OWNED_BY")  # goog-dm label

    def test_iam_recommender(self, sourced):
        rec = "//recommender.googleapis.com/projects/proj-a/iamPolicyRecommender"
        assert by_arn(sourced["assets"], rec).asset_type == AssetType.ACCESS_ANALYZER
        assert edge(
            sourced, rec, "//cloudidentity.googleapis.com/groups/g1", E.MONITORS, "FINDING_AFFECTS"
        )

    def test_dlp_placeholder(self, sourced):
        ph = by_arn(sourced["assets"], "cloudg:gcp:dlp-discovery:projects/proj-a:not-enabled")
        assert ph.asset_type == AssetType.DATA_SECURITY_SCANNER

    def test_rest_requests_stay_on_the_fake(self, sourced):
        urls = sourced["session"].urls() + sourced["session"].urls("POST")
        assert urls and all(u.startswith("https://") and ".googleapis.com/" in u for u in urls)


class TestCoverage:
    def test_source_records(self, sourced):
        st = sourced["status"]
        for name in SOURCES:
            assert f"gcp_{name}" in st, name
        assert st["gcp_dns_records"].status == ServiceStatus.SUCCESS
        assert st["gcp_dns_records"].asset_count == 2
        assert st["gcp_scc"].status == ServiceStatus.SUCCESS
        assert st["gcp_iam_policies"].status == ServiceStatus.SUCCESS

    def test_family_records(self, sourced):
        st = sourced["status"]
        assert st["gcp_assets_network"].status == ServiceStatus.SUCCESS
        assert st["gcp_assets_network"].asset_count >= 2
        assert st["gcp_assets_dns"].asset_count == 1
        assert "gcp_assets_ml" in st  # recorded even when empty

    def _run(self, routes, **kw):
        rest, _ = rest_client(routes)
        cov = CollectionCoverage(provider="gcp")
        client = FakeAssetClient(resources=RESOURCES, iam=IAM)
        collector = GCPDeepInventoryCollector(
            PROJECT, client=client, rest_client=rest, coverage=cov, **kw
        )
        run(collector.collect())
        return {s.service: s for s in cov.services}

    def test_disabled_everywhere_is_skipped(self):
        routes = {
            f"https://backupdr.googleapis.com/v1/projects/proj-a/locations/-/{k}": disabled(
                "backupdr.googleapis.com"
            )
            for k in ("backupVaults", "backupPlans", "backupPlanAssociations", "managementServers")
        }
        st = self._run(routes, services=["backup"])
        assert st["gcp_backup_dr"].status == ServiceStatus.SKIPPED
        assert "not enabled" in st["gcp_backup_dr"].error

    def test_denied_everywhere_is_failed(self):
        routes = {
            "https://deploymentmanager.googleapis.com/deploymentmanager/v2/projects/proj-a/global/deployments": denied()
        }
        st = self._run(routes, services=["deployment_manager"])
        assert st["gcp_deployment_manager"].status == ServiceStatus.FAILED

    def test_no_transport_is_skipped(self):
        cov = CollectionCoverage(provider="gcp")
        collector = GCPDeepInventoryCollector(
            PROJECT, client=FakeAssetClient(resources=RESOURCES), coverage=cov
        )
        run(collector.collect())
        st = {s.service: s for s in cov.services}
        assert st["gcp_scc"].status == ServiceStatus.SKIPPED
        assert "no REST transport" in st["gcp_scc"].error
        assert st["gcp_iam_roles"].status == ServiceStatus.SUCCESS  # no API needed

    def test_missing_customer_is_skipped(self):
        cov = CollectionCoverage(provider="gcp")
        rest, _ = rest_client({})
        collector = GCPDeepInventoryCollector(
            PROJECT,
            client=FakeAssetClient(resources=[PROJECT_ASSET]),
            rest_client=rest,
            coverage=cov,
        )
        run(collector.collect())
        st = {s.service: s for s in cov.services}
        assert st["gcp_cloud_identity"].status == ServiceStatus.SKIPPED

    def test_raising_source_is_failed_and_run_goes_on(self, monkeypatch):
        from cloudg.inventory.gcp_sources import base

        def boom(ctx, run):
            raise RuntimeError("boom")

        monkeypatch.setitem(base.SOURCES, "dns_records", base.Source("dns_records", "dns", boom))
        st = self._run(ROUTES)
        assert st["gcp_dns_records"].status == ServiceStatus.FAILED
        assert "boom" in st["gcp_dns_records"].error
        assert st["gcp_scc"].status == ServiceStatus.SUCCESS

    def test_deep_sources_off(self):
        st = self._run(ROUTES, deep_sources=False)
        assert not any(k == "gcp_scc" for k in st)
        assert st["gcp_iam_policies"].status == ServiceStatus.SUCCESS


class TestServiceFiltering:
    def test_family_lookup(self):
        assert gcp_family("compute.googleapis.com/Instance") == "compute"
        assert gcp_family("compute.googleapis.com/Network") == "network"
        assert gcp_family("pubsub.googleapis.com/Topic") == "integration"
        assert gcp_family("k8s.io/Pod") == "containers"
        assert gcp_family("widgets.googleapis.com/Widget") == "other"
        assert {"network", "security", "identity", "dns", "backup"} <= set(families())

    def test_selection_rules(self):
        assert is_selected("dns_records", "dns", None, None)
        assert is_selected("dns_records", "dns", ["dns"], None)
        assert not is_selected("dns_records", "dns", ["network"], None)
        assert not is_selected("dns_records", "dns", None, ["dns_records"])
        assert is_selected("cloudresourcemanager", "hierarchy", ["network"], None)
        assert not is_selected("cloudresourcemanager", "hierarchy", None, ["hierarchy"])
        assert type_selected("pubsub.googleapis.com/Topic", ["pubsub"])
        assert type_selected("pubsub.googleapis.com/Topic", ["pubsub.googleapis.com/Topic"])
        assert not type_selected("pubsub.googleapis.com/Topic", None, ["integration"])

    def test_include_only_network(self):
        rest, session = rest_client(ROUTES)
        cov = CollectionCoverage(provider="gcp")
        collector = GCPDeepInventoryCollector(
            PROJECT,
            client=FakeAssetClient(resources=RESOURCES, iam=IAM),
            rest_client=rest,
            coverage=cov,
            services=["network"],
        )
        assets = run(collector.collect())
        types = {a.metadata.get("gcp_asset_type") for a in assets}
        assert "compute.googleapis.com/Network" in types
        assert "cloudresourcemanager.googleapis.com/Project" in types  # hierarchy kept
        assert "pubsub.googleapis.com/Topic" not in types
        assert "compute.googleapis.com/Instance" not in types
        services = {s.service for s in cov.services}
        assert "gcp_assets_network" in services and "gcp_assets_data" not in services
        assert "gcp_scc" not in services and "gcp_iam_policies" not in services
        assert session.calls == []

    def test_exclude_wins(self):
        rest, session = rest_client(ROUTES)
        cov = CollectionCoverage(provider="gcp")
        collector = GCPDeepInventoryCollector(
            PROJECT,
            client=FakeAssetClient(resources=RESOURCES, iam=IAM),
            rest_client=rest,
            coverage=cov,
            exclude_services=["dns", "scc", "pubsub"],
        )
        assets = run(collector.collect())
        assert not any(a.asset_type == AssetType.DNS_ZONE for a in assets)
        assert not any(
            a.metadata.get("gcp_asset_type") == "pubsub.googleapis.com/Topic" for a in assets
        )
        services = {s.service for s in cov.services}
        assert "gcp_dns_records" not in services and "gcp_scc" not in services
        assert "gcp_monitoring" in services
        assert not any("dns.googleapis.com" in u or "securitycenter" in u for u in session.urls())

    def test_mapper_binds_inventory_and_gcp_config(self):
        from cloudg.config import CloudGConfig
        from cloudg.inventory.mapper import InventoryMapper

        cfg = CloudGConfig(
            providers=["gcp"],
            gcp={
                "project_ids": [PROJECT],
                "cloud_identity_customer_id": "C9",
                "max_dns_records_per_zone": 7,
            },
            inventory={"services": ["network", "dns"], "exclude_services": ["dns_records"]},
        )
        gcp_cls = InventoryMapper(cfg)._collector_overrides()["gcp"]
        collector = gcp_cls(PROJECT, client=FakeAssetClient())
        assert issubclass(gcp_cls, GCPDeepInventoryCollector) and gcp_cls.supports_org_scope
        assert collector._services == ["network", "dns"]
        assert collector._exclude_services == ["dns_records"]
        assert collector._source_options.customer_id == "C9"
        assert collector._source_options.max_dns_records_per_zone == 7

    def test_options_from_config_defaults(self):
        assert deep_options_from_config() == {}


class TestRestClient:
    def test_pagination_and_cap(self):
        rest, session = rest_client(
            {
                "https://x.googleapis.com/v1/items": [
                    {"items": [{"n": 1}, {"n": 2}], "nextPageToken": "t"},
                    {"items": [{"n": 3}]},
                ]
            }
        )
        items, truncated = rest.list("https://x.googleapis.com/v1/items", "items", page_size=2)
        assert [i["n"] for i in items] == [1, 2, 3] and truncated is False
        assert session.calls[1][2]["pageToken"] == "t"
        rest, _ = rest_client(
            {"https://x.googleapis.com/v1/items": {"items": [{"n": 1}, {"n": 2}]}}
        )
        items, truncated = rest.list("https://x.googleapis.com/v1/items", "items", max_items=1)
        assert len(items) == 1 and truncated is True

    def test_retries_throttling_then_succeeds(self):
        slept: list[float] = []
        rest, session = rest_client(
            {
                "https://x.googleapis.com/v1/a": [
                    FakeResponse(429, {}, {"Retry-After": "2"}),
                    FakeResponse(503, {}),
                    {"ok": True},
                ]
            },
            sleep=slept.append,
        )
        assert rest.get("https://x.googleapis.com/v1/a") == {"ok": True}
        assert len(session.calls) == 3 and slept[0] == 2.0

    def test_errors(self):
        rest, _ = rest_client(
            {
                "https://x.googleapis.com/v1/off": disabled(),
                "https://x.googleapis.com/v1/no": denied(),
                "https://x.googleapis.com/v1/auth": FakeResponse(401, {}),
                "https://x.googleapis.com/v1/pre": api_error(
                    400, "FAILED_PRECONDITION", message="not activated"
                ),
            }
        )
        with pytest.raises(GCPApiError) as off:
            rest.get("https://x.googleapis.com/v1/off")
        assert off.value.disabled and off.value.status_code == 403
        with pytest.raises(GCPApiError) as no:
            rest.get("https://x.googleapis.com/v1/no")
        assert not no.value.disabled and no.value.error_code == "PERMISSION_DENIED"
        with pytest.raises(CredentialError):
            rest.get("https://x.googleapis.com/v1/auth")
        with pytest.raises(GCPApiError) as pre:
            rest.get("https://x.googleapis.com/v1/pre")
        assert pre.value.precondition
        with pytest.raises(GCPApiError) as missing:
            rest.get("https://x.googleapis.com/v1/none")
        assert missing.value.not_found

    def test_post(self):
        rest, session = rest_client(
            {"https://x.googleapis.com/v3/p:getIamPolicy": lambda body: {"echo": body}}
        )
        assert rest.post("https://x.googleapis.com/v3/p:getIamPolicy", {"a": 1}) == {
            "echo": {"a": 1}
        }
        assert session.calls[0][0] == "POST"

    def test_missing_requests_transport(self, monkeypatch):
        import builtins

        from cloudg.exceptions import ProviderSDKMissingError
        from cloudg.inventory.gcp_sources import GCPRestClient

        real = builtins.__import__

        def fake_import(name, *a, **k):
            if name == "google.auth.transport.requests":
                raise ImportError(name)
            return real(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(ProviderSDKMissingError):
            GCPRestClient(object()).get("https://x.googleapis.com/v1/a")
