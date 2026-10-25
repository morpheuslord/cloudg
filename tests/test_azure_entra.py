"""Azure parity: Entra ID through Microsoft Graph, and its merge with RBAC grants."""

from __future__ import annotations

import asyncio

import pytest

from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.exceptions import CredentialError
from cloudg.inventory.azure_entra import MICROSOFT_GRAPH_APP_ID, discover_entra
from cloudg.inventory.linker import RelationshipLinker
from cloudg.inventory.mapper import deduplicate
from cloudg.schema.models import AssetType, EdgeType
from tests.azure_fakes import FakeArm, TypedFakeGraph
from tests.test_azure_inventory import SUB, _Graph

TENANT = "dddd0000-0000-0000-0000-000000000000"
ALICE = "a1110000-0000-0000-0000-000000000001"
GUEST = "a1110000-0000-0000-0000-000000000002"
ADMINS = "a1110000-0000-0000-0000-000000000003"
APP_OBJ = "a1110000-0000-0000-0000-000000000004"
APP_ID = "a1110000-0000-0000-0000-0000000000a1"
APP_SP = "a1110000-0000-0000-0000-000000000005"
GRAPH_SP = "a1110000-0000-0000-0000-000000000006"
MI_SP = "a1110000-0000-0000-0000-000000000007"
EXT_SP = "a1110000-0000-0000-0000-000000000008"
GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"
READER_ROLE = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
ROLEMGMT = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"


def _routes() -> dict:
    v = "/v1.0"
    return {
        f"{v}/organization": [
            {
                "id": TENANT,
                "displayName": "Contoso",
                "tenantType": "AAD",
                "verifiedDomains": [{"name": "contoso.com"}],
            }
        ],
        f"{v}/users": [
            {
                "id": ALICE,
                "displayName": "Alice",
                "userPrincipalName": "alice@contoso.com",
                "userType": "Member",
                "accountEnabled": True,
            },
            {
                "id": GUEST,
                "displayName": "Partner",
                "userPrincipalName": "partner_ext#EXT#@contoso.com",
                "userType": "Guest",
            },
        ],
        f"{v}/groups": [
            {
                "id": ADMINS,
                "displayName": "Cloud Admins",
                "securityEnabled": True,
                "isAssignableToRole": True,
            }
        ],
        f"{v}/groups/{ADMINS}/members": [{"id": ALICE}, {"id": APP_SP}],
        f"{v}/applications": [
            {
                "id": APP_OBJ,
                "appId": APP_ID,
                "displayName": "deployer",
                "signInAudience": "AzureADMultipleOrgs",
                "passwordCredentials": [
                    {"endDateTime": "2027-01-01T00:00:00Z", "secretText": None}
                ],
                "keyCredentials": [],
                "requiredResourceAccess": [
                    {"resourceAppId": MICROSOFT_GRAPH_APP_ID, "resourceAccess": [{"id": ROLEMGMT}]}
                ],
            }
        ],
        f"{v}/applications/{APP_OBJ}/owners": [{"id": ALICE}],
        f"{v}/applications/{APP_OBJ}/federatedIdentityCredentials": [
            {
                "name": "gha",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:contoso/infra:environment:prod",
            },
        ],
        f"{v}/servicePrincipals": [
            {
                "id": APP_SP,
                "appId": APP_ID,
                "displayName": "deployer",
                "servicePrincipalType": "Application",
                "appOwnerOrganizationId": TENANT,
                "appRoles": [],
            },
            {
                "id": GRAPH_SP,
                "appId": MICROSOFT_GRAPH_APP_ID,
                "displayName": "Microsoft Graph",
                "servicePrincipalType": "Application",
                "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                "appRoles": [{"id": ROLEMGMT, "value": "RoleManagement.ReadWrite.Directory"}],
            },
            {
                "id": MI_SP,
                "appId": "mi-app",
                "displayName": "id-web",
                "servicePrincipalType": "ManagedIdentity",
            },
            {
                "id": EXT_SP,
                "appId": "ext-app",
                "displayName": "Vendor SaaS",
                "servicePrincipalType": "Application",
                "appOwnerOrganizationId": "eeee0000-0000-0000-0000-000000000000",
            },
        ],
        f"{v}/servicePrincipals/{APP_SP}/owners": [{"id": ALICE}],
        f"{v}/servicePrincipals/{EXT_SP}/owners": [],
        f"{v}/servicePrincipals/{GRAPH_SP}/appRoleAssignedTo": [
            {
                "principalId": APP_SP,
                "principalType": "ServicePrincipal",
                "appRoleId": ROLEMGMT,
                "resourceId": GRAPH_SP,
            },
            {
                "principalId": MI_SP,
                "principalType": "ServicePrincipal",
                "appRoleId": ROLEMGMT,
                "resourceId": GRAPH_SP,
            },
        ],
        f"{v}/oauth2PermissionGrants": [
            {
                "clientId": EXT_SP,
                "resourceId": GRAPH_SP,
                "consentType": "AllPrincipals",
                "scope": "User.Read Mail.ReadWrite",
            },
        ],
        f"{v}/roleManagement/directory/roleDefinitions": [
            {
                "id": GA_ROLE,
                "displayName": "Global Administrator",
                "templateId": GA_ROLE,
                "isBuiltIn": True,
                "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/*/allTasks"]}],
            },
            {
                "id": READER_ROLE,
                "displayName": "Directory Readers",
                "templateId": READER_ROLE,
                "isBuiltIn": True,
            },
        ],
        f"{v}/roleManagement/directory/roleAssignments": [
            {
                "id": "ra1",
                "principalId": ADMINS,
                "roleDefinitionId": READER_ROLE,
                "directoryScopeId": "/",
            },
        ],
        f"{v}/roleManagement/directory/roleEligibilitySchedules": [
            {
                "id": "es1",
                "principalId": ALICE,
                "roleDefinitionId": GA_ROLE,
                "directoryScopeId": "/",
                "memberType": "Direct",
            },
        ],
    }


def _graph(assets):
    linker = RelationshipLinker(assets)
    edges = linker.link()
    return _Graph(assets + linker.external_assets, edges)


@pytest.fixture(scope="module")
def entra():
    cov = CollectionCoverage(provider="azure", region="global")
    client = FakeArm(_routes())
    assets = discover_entra(object(), lambda cred: client, coverage=cov)
    return assets, {s.service: s for s in cov.services}, client


class TestEntraObjects:
    def test_types_and_tenant(self, entra):
        assets, _cov, _ = entra
        g = _graph(assets)
        assert g.a(f"entra:tenant/{TENANT}").asset_type == AssetType.ORGANIZATION
        alice = g.a(f"entra:principal/{ALICE}")
        assert alice.asset_type == AssetType.IDENTITY_USER
        assert alice.metadata["user_principal_name"] == "alice@contoso.com"
        assert "discovered_via" not in alice.metadata  # real object: wins over placeholders
        assert g.a(f"entra:principal/{GUEST}").metadata["guest"] is True
        assert g.a(f"entra:principal/{ADMINS}").asset_type == AssetType.IDENTITY_GROUP
        app = g.a(f"entra:application/{APP_OBJ}")
        assert app.asset_type == AssetType.APP_REGISTRATION
        assert app.metadata["multi_tenant"] is True
        assert app.metadata["secrets"] == {"count": 1, "latest_expiry": "2027-01-01T00:00:00Z"}
        sp = g.a(f"entra:principal/{APP_SP}")
        assert sp.asset_type == AssetType.SERVICE_PRINCIPAL
        # managed identities belong to the resources that own them
        assert f"entra:principal/{MI_SP}" not in g.by_arn
        assert g.a(f"entra:principal/{EXT_SP}").metadata["external_application"] is True

    def test_membership_and_ownership(self, entra):
        g = _graph(entra[0])
        group = f"entra:principal/{ADMINS}"
        assert g.has(group, f"entra:principal/{ALICE}", EdgeType.CONTAINS)
        assert g.has(group, f"entra:principal/{APP_SP}", EdgeType.CONTAINS)
        app = f"entra:application/{APP_OBJ}"
        assert g.has(f"entra:principal/{ALICE}", app, EdgeType.MANAGES, "OWNED_BY")
        assert g.has(app, f"entra:principal/{APP_SP}", EdgeType.MANAGES, "OWNED_BY")
        assert g.has(
            f"entra:principal/{ALICE}", f"entra:principal/{APP_SP}", EdgeType.MANAGES, "OWNED_BY"
        )

    def test_federated_credentials(self, entra):
        assets, _, _ = entra
        app = next(a for a in assets if a.arn == f"entra:application/{APP_OBJ}")
        trust = [r for r in app.metadata["relations"] if r["edge"] == "IAM_TRUST"]
        assert trust[0]["relationship"] == "CROSS_ACCOUNT_TRUST"
        assert trust[0]["properties"]["subject"].startswith("repo:contoso/infra")
        assert app.metadata["federated_credentials"][0]["name"] == "gha"

    def test_app_roles_and_grants(self, entra):
        g = _graph(entra[0])
        graph_sp = f"entra:principal/{GRAPH_SP}"
        edge = g.edge(f"entra:principal/{APP_SP}", graph_sp, EdgeType.GRANTS_ACCESS)
        assert edge.properties["role"] == "RoleManagement.ReadWrite.Directory"
        assert edge.properties["privileged"] is True
        grant = g.edge(f"entra:principal/{EXT_SP}", graph_sp, EdgeType.GRANTS_ACCESS)
        assert grant.properties["delegated"] is True
        assert grant.properties["privileged"] is True  # Mail.ReadWrite for all users

    def test_directory_roles_and_pim(self, entra):
        g = _graph(entra[0])
        ga = g.a(f"entra:directoryRole/{GA_ROLE}")
        assert ga.asset_type == AssetType.IAM_POLICY and ga.metadata["privileged"] is True
        attach = g.edge(f"entra:principal/{ALICE}", ga.arn, EdgeType.IAM_POLICY_ATTACHMENT)
        assert attach.relationship == "USER_HAS_POLICY" and attach.properties["eligible"] is True
        assert g.has(
            f"entra:principal/{ADMINS}",
            f"entra:directoryRole/{READER_ROLE}",
            EdgeType.IAM_POLICY_ATTACHMENT,
            "GROUP_HAS_POLICY",
        )
        tenant = g.edge(
            f"entra:principal/{ALICE}", f"entra:tenant/{TENANT}", EdgeType.GRANTS_ACCESS
        )
        assert tenant.properties["privileged"] is True and tenant.properties["eligible"] is True

    def test_coverage(self, entra):
        cov = entra[1]
        for task in (
            "entra_tenant",
            "entra_users",
            "entra_groups",
            "entra_applications",
            "entra_service_principals",
            "entra_group_members",
            "entra_app_role_assignments",
            "entra_oauth2_grants",
            "entra_directory_roles",
            "entra_pim_eligibility",
        ):
            assert cov[task].status == ServiceStatus.SUCCESS, (task, cov[task].error)
        assert cov["entra_users"].asset_count == 2


def test_missing_graph_permission_is_partial_not_fatal():
    routes = _routes()
    client = FakeArm(routes, forbidden={"/roleeligibilityschedules", "/oauth2permissiongrants"})
    cov = CollectionCoverage(provider="azure")
    assets = discover_entra(object(), lambda cred: client, coverage=cov)
    status = {s.service: s for s in cov.services}
    assert status["entra_pim_eligibility"].status == ServiceStatus.FAILED
    assert "Graph permission missing" in status["entra_pim_eligibility"].error
    assert status["entra_oauth2_grants"].status == ServiceStatus.FAILED
    assert status["entra_users"].status == ServiceStatus.SUCCESS
    assert any(a.asset_type == AssetType.IDENTITY_USER for a in assets)


def test_no_token_raises_credential_error():
    with pytest.raises(CredentialError):
        discover_entra(object())  # default client: object() cannot issue tokens


def test_entra_objects_merge_with_rbac_placeholders():
    """An RBAC grant to an Entra user lands on the real user after dedupe."""
    from cloudg.inventory.azure_deep import AzureDeepInventoryCollector

    rows = {
        "authorizationresources": [
            {
                "id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/r1",
                "type": "microsoft.authorization/roleassignments",
                "subscriptionId": SUB,
                "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "roleName": "Owner",
                "principalId": ALICE,
                "principalType": "User",
                "scope": f"/subscriptions/{SUB}",
                "properties": {},
            }
        ],
    }
    collector = AzureDeepInventoryCollector(
        object(), SUB, graph_client_factory=lambda c: TypedFakeGraph(rows)
    )
    sub_assets = asyncio.run(collector.collect())
    entra_assets = discover_entra(object(), lambda cred: FakeArm(_routes()))
    merged, _ = deduplicate(entra_assets + sub_assets, [])
    alice = [a for a in merged if a.arn == f"entra:principal/{ALICE}"]
    assert len(alice) == 1 and alice[0].metadata["user_principal_name"] == "alice@contoso.com"
    g = _graph(merged)
    assert g.has(
        f"entra:principal/{ALICE}",
        f"/subscriptions/{SUB}",
        EdgeType.GRANTS_ACCESS,
        "POLICY_ALLOWS_ACTION",
    )
