"""Azure parity: Resource Graph tables beyond ``resources``, coverage and filtering."""

from __future__ import annotations

import asyncio

import pytest

from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.inventory.azure_graph.families import (
    TaskRecorder,
    family_of_type,
    row_filter,
    select_azure_tasks,
)
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType
from tests.azure_fakes import collect_linked
from tests.test_azure_inventory import SUB, _row

RG = f"/subscriptions/{SUB}/resourceGroups/rg-gov"
SUB_REF = f"/subscriptions/{SUB}"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-db"
VM2 = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-dr"
ST = f"{RG}/providers/Microsoft.Storage/storageAccounts/stgov"
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-gov"
AKS = f"{RG}/providers/Microsoft.ContainerService/managedClusters/aks-gov"
ACR = f"{RG}/providers/Microsoft.ContainerRegistry/registries/acrgov"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet-spoke"
HUB_VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet-hub"
RSV = f"{RG}/providers/Microsoft.RecoveryServices/vaults/rsv-gov"
BVAULT = f"{RG}/providers/Microsoft.DataProtection/backupVaults/bv-gov"
LAW = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-gov"
DCR = f"{RG}/providers/Microsoft.Insights/dataCollectionRules/dcr-vm"
MAINT = f"{RG}/providers/Microsoft.Maintenance/maintenanceConfigurations/patch-weekly"
AVNM = f"{RG}/providers/Microsoft.Network/networkManagers/avnm"
NG = f"{AVNM}/networkGroups/spokes"
CONN_CFG = f"{AVNM}/connectivityConfigurations/hub-spoke"
ADMIN_CFG = f"{AVNM}/securityAdminConfigurations/baseline"
RULE_COLL = f"{ADMIN_CFG}/ruleCollections/deny-inbound"

DENY_DEF = "/providers/Microsoft.Authorization/policyDefinitions/deny-public-ip"
AUDIT_DEF = "/providers/Microsoft.Authorization/policyDefinitions/audit-diag"
INITIATIVE = f"{SUB_REF}/providers/Microsoft.Authorization/policySetDefinitions/baseline"
ASSIGN_DENY = f"{SUB_REF}/providers/Microsoft.Authorization/policyAssignments/deny-pip"
ASSIGN_OFF = f"{RG}/providers/Microsoft.Authorization/policyAssignments/deny-pip-off"
ASSIGN_SET = f"{SUB_REF}/providers/Microsoft.Authorization/policyAssignments/baseline"
EXEMPTION = f"{RG}/providers/Microsoft.Authorization/policyExemptions/legacy"

OWNER_GUID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CUSTOM_GUID = "11112222-3333-4444-5555-666677778888"
USER_OID = "aaaa0000-0000-0000-0000-000000000001"
SP_OID = "aaaa0000-0000-0000-0000-000000000002"
GROUP_OID = "aaaa0000-0000-0000-0000-000000000003"
MG = "/providers/Microsoft.Management/managementGroups/corp"
MGROOT = "/providers/Microsoft.Management/managementGroups/tenant-root"


def _deny_definition(name: str, effect: str = "[parameters('effect')]") -> dict:
    return {
        "displayName": name,
        "policyType": "Custom",
        "mode": "All",
        "parameters": {"effect": {"defaultValue": "Deny"}},
        "policyRule": {"if": {"field": "type"}, "then": {"effect": effect}},
    }


def _resource_rows() -> list[dict]:
    return [
        _row(VM, "microsoft.compute/virtualmachines"),
        _row(VM2, "microsoft.compute/virtualmachines"),
        _row(ST, "microsoft.storage/storageaccounts"),
        _row(KV, "microsoft.keyvault/vaults"),
        _row(AKS, "microsoft.containerservice/managedclusters"),
        _row(ACR, "microsoft.containerregistry/registries"),
        _row(VNET, "microsoft.network/virtualnetworks"),
        _row(HUB_VNET, "microsoft.network/virtualnetworks"),
        _row(
            RSV,
            "microsoft.recoveryservices/vaults",
            {
                "securitySettings": {
                    "immutabilitySettings": {"state": "Locked"},
                    "softDeleteSettings": {"softDeleteState": "AlwaysON"},
                },
                "encryption": {
                    "keyVaultProperties": {"keyUri": "https://kv-gov.vault.azure.net/keys/cmk"}
                },
            },
        ),
        _row(BVAULT, "microsoft.dataprotection/backupvaults"),
        _row(LAW, "microsoft.operationalinsights/workspaces", {"customerId": "C-1"}),
        _row(
            DCR,
            "microsoft.insights/datacollectionrules",
            {
                "destinations": {"logAnalytics": [{"workspaceResourceId": LAW, "name": "la"}]},
                "dataFlows": [{"streams": ["Microsoft-Syslog"]}],
            },
        ),
        _row(
            MAINT,
            "microsoft.maintenance/maintenanceconfigurations",
            {
                "maintenanceScope": "InGuestPatch",
                "maintenanceWindow": {"recurEvery": "Week Saturday"},
            },
        ),
        _row(
            AVNM,
            "microsoft.network/networkmanagers",
            {
                "networkManagerScopes": {"subscriptions": [SUB_REF]},
                "networkManagerScopeAccesses": ["Connectivity", "SecurityAdmin"],
            },
        ),
    ]


def _policy_rows() -> list[dict]:
    return [
        _row(
            ASSIGN_DENY,
            "microsoft.authorization/policyassignments",
            {
                "displayName": "Deny public IPs",
                "scope": SUB_REF,
                "policyDefinitionId": DENY_DEF,
                "enforcementMode": "Default",
                "parameters": {"effect": {"value": "Deny"}},
            },
            resourceGroup="",
        ),
        _row(
            ASSIGN_OFF,
            "microsoft.authorization/policyassignments",
            {
                "displayName": "Deny public IPs (audit only)",
                "scope": RG,
                "policyDefinitionId": DENY_DEF,
                "enforcementMode": "DoNotEnforce",
            },
        ),
        _row(
            ASSIGN_SET,
            "microsoft.authorization/policyassignments",
            {
                "displayName": "Baseline",
                "scope": SUB_REF,
                "policyDefinitionId": INITIATIVE,
            },
            resourceGroup="",
        ),
        _row(
            EXEMPTION,
            "microsoft.authorization/policyexemptions",
            {
                "policyAssignmentId": ASSIGN_DENY,
                "exemptionCategory": "Waiver",
            },
        ),
        {
            "id": DENY_DEF,
            "name": "deny-public-ip",
            "type": "microsoft.authorization/policydefinitions",
            "properties": _deny_definition("Deny public IP"),
        },
        {
            "id": AUDIT_DEF,
            "name": "audit-diag",
            "type": "microsoft.authorization/policydefinitions",
            "properties": {
                **_deny_definition("Audit diagnostics", "AuditIfNotExists"),
                "policyType": "BuiltIn",
            },
        },
        {
            "id": INITIATIVE,
            "name": "baseline",
            "type": "microsoft.authorization/policysetdefinitions",
            "subscriptionId": SUB,
            "properties": {
                "displayName": "Baseline",
                "policyType": "Custom",
                "policyDefinitions": [
                    {"policyDefinitionId": AUDIT_DEF},
                    {"policyDefinitionId": DENY_DEF},
                ],
            },
        },
        {
            "id": f"{VM}/providers/Microsoft.PolicyInsights/policyStates/latest-1",
            "type": "microsoft.policyinsights/policystates",
            "subscriptionId": SUB,
            "resourceId": VM,
            "policyAssignmentId": ASSIGN_SET.lower(),
            "policyDefinitionId": AUDIT_DEF,
            "policyDefinitionAction": "auditifnotexists",
            "complianceState": "NonCompliant",
        },
    ]


def _authorization_rows() -> list[dict]:
    def ra(name, pid, ptype, scope, guid, role_name=None, sub=SUB):
        return {
            "id": f"{scope.rstrip('/')}/providers/Microsoft.Authorization/roleAssignments/{name}",
            "name": name,
            "type": "microsoft.authorization/roleassignments",
            "subscriptionId": sub,
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{guid}",
            "roleGuid": guid,
            "roleName": role_name,
            "principalId": pid,
            "principalType": ptype,
            "scope": scope,
            "properties": {},
        }

    return [
        ra("ra-user", USER_OID, "User", SUB_REF, OWNER_GUID, "Owner"),
        ra("ra-sp", SP_OID, "ServicePrincipal", ST, CUSTOM_GUID, "Storage Operator"),
        ra("ra-mg", GROUP_OID, "Group", MG, OWNER_GUID, "Owner", sub=""),
        ra(
            "ra-other-mg",
            USER_OID,
            "User",
            "/providers/Microsoft.Management/managementGroups/other",
            OWNER_GUID,
            "Owner",
            sub="",
        ),
        {
            "id": f"/providers/Microsoft.Authorization/roleDefinitions/{OWNER_GUID}",
            "name": OWNER_GUID,
            "type": "microsoft.authorization/roledefinitions",
            "roleGuid": OWNER_GUID,
            "properties": {
                "roleName": "Owner",
                "type": "BuiltInRole",
                "permissions": [{"actions": ["*"], "notActions": []}],
                "assignableScopes": ["/"],
            },
        },
        {
            "id": f"{SUB_REF}/providers/Microsoft.Authorization/roleDefinitions/{CUSTOM_GUID}",
            "name": CUSTOM_GUID,
            "type": "microsoft.authorization/roledefinitions",
            "roleGuid": CUSTOM_GUID,
            "properties": {
                "roleName": "Storage Operator",
                "type": "CustomRole",
                "permissions": [{"actions": ["Microsoft.Storage/storageAccounts/listKeys/action"]}],
                "assignableScopes": [SUB_REF],
            },
        },
    ]


def _security_rows() -> list[dict]:
    return [
        {
            "id": f"{SUB_REF}/providers/Microsoft.Security/pricings/VirtualMachines",
            "name": "VirtualMachines",
            "type": "microsoft.security/pricings",
            "properties": {"pricingTier": "Standard"},
        },
        {
            "id": f"{SUB_REF}/providers/Microsoft.Security/pricings/StorageAccounts",
            "name": "StorageAccounts",
            "type": "microsoft.security/pricings",
            "properties": {
                "pricingTier": "Standard",
                "extensions": [{"name": "OnUploadMalwareScanning", "isEnabled": "True"}],
            },
        },
        {
            "id": f"{VM2}/providers/Microsoft.Security/pricings/VirtualMachines",
            "name": "VirtualMachines",
            "type": "microsoft.security/pricings",
            "properties": {"pricingTier": "Free"},
        },
        {
            "id": f"{VM}/providers/Microsoft.Security/assessments/a1",
            "type": "microsoft.security/assessments",
            "resourceId": VM,
            "code": "Unhealthy",
            "severity": "High",
            "title": "Machines should have vulnerability findings resolved",
        },
        {
            "id": f"{ST}/providers/Microsoft.Security/assessments/a2",
            "type": "microsoft.security/assessments",
            "resourceId": ST,
            "code": "Healthy",
            "severity": "Low",
            "title": "Secure transfer should be enabled",
        },
        {
            "id": f"{ACR}/providers/Microsoft.Security/assessments/a3/subassessments/cve-1",
            "type": "microsoft.security/assessments/subassessments",
            "resourceId": ACR,
            "code": "Unhealthy",
            "severity": "High",
            "title": "CVE-2024-0001",
            "additionalData": {"repositoryName": "payments/api"},
        },
        {
            "id": f"{SUB_REF}/providers/Microsoft.Security/secureScores/ascScore",
            "name": "ascScore",
            "type": "microsoft.security/securescores",
            "properties": {"score": {"current": 31.5, "max": 58, "percentage": 0.54}},
        },
        {
            "id": f"{SUB_REF}/providers/Microsoft.Security/secureScores/ascScore/secureScoreControls/mfa",
            "name": "mfa",
            "type": "microsoft.security/securescores/securescorecontrols",
            "properties": {
                "displayName": "Enable MFA",
                "score": {"current": 0, "max": 10},
                "unhealthyResourceCount": 3,
            },
        },
        {
            "id": f"{SUB_REF}/resourceGroups/rg-gov/providers/Microsoft.Security/locations/westeurope/alerts/al1",
            "name": "al1",
            "type": "microsoft.security/locations/alerts",
            "properties": {
                "alertDisplayName": "Suspicious login",
                "severity": "High",
                "Status": "Active",
                "resourceIdentifiers": [{"type": "AzureResource", "azureResourceId": VM}],
            },
        },
    ]


def _recovery_rows() -> list[dict]:
    pol = f"{RSV}/backupPolicies/daily"
    return [
        {
            "id": pol,
            "name": "daily",
            "type": "microsoft.recoveryservices/vaults/backuppolicies",
            "subscriptionId": SUB,
            "properties": {
                "backupManagementType": "AzureIaasVM",
                "schedulePolicy": {"scheduleRunFrequency": "Daily"},
                "protectedItemsCount": 1,
            },
        },
        {
            "id": f"{RSV}/backupFabrics/Azure/protectionContainers/iaasvm;rg-gov;vm-db/protectedItems/vm;vm-db",
            "name": "vm;vm-db",
            "type": "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems",
            "subscriptionId": SUB,
            "properties": {
                "sourceResourceId": VM,
                "policyId": pol,
                "workloadType": "VM",
                "protectionState": "Protected",
            },
        },
        {
            "id": f"{BVAULT}/backupInstances/st-blobs",
            "name": "st-blobs",
            "type": "microsoft.dataprotection/backupvaults/backupinstances",
            "subscriptionId": SUB,
            "properties": {
                "dataSourceInfo": {
                    "resourceID": ST,
                    "datasourceType": "Microsoft.Storage/storageAccounts/blobServices",
                },
                "policyInfo": {"policyId": f"{BVAULT}/backupPolicies/blob"},
            },
        },
        {
            "id": f"{RSV}/replicationFabrics/f1/replicationProtectionContainers/c1/replicationProtectedItems/vm-db",
            "name": "vm-db",
            "type": "microsoft.recoveryservices/vaults/replicationfabrics/replicationprotectioncontainers/replicationprotecteditems",
            "subscriptionId": SUB,
            "properties": {
                "replicationHealth": "Normal",
                "providerSpecificDetails": {
                    "fabricObjectId": VM,
                    "recoveryAzureVMId": VM2,
                    "recoveryAzureLocation": "northeurope",
                },
            },
        },
    ]


def _k8s_config_rows() -> list[dict]:
    return [
        _row(
            f"{AKS}/providers/Microsoft.KubernetesConfiguration/extensions/flux",
            "microsoft.kubernetesconfiguration/extensions",
            {"extensionType": "microsoft.flux", "version": "1.8.0"},
        ),
        _row(
            f"{AKS}/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/apps",
            "microsoft.kubernetesconfiguration/fluxconfigurations",
            {
                "sourceKind": "GitRepository",
                "gitRepository": {
                    "url": "https://github.com/contoso/gitops.git",
                    "repositoryRef": {"branch": "main"},
                },
                "kustomizations": {"apps": {"path": "./apps"}},
            },
        ),
    ]


def _network_rows() -> list[dict]:
    return [
        _row(
            NG, "microsoft.network/networkmanagers/networkgroups", {"memberType": "VirtualNetwork"}
        ),
        _row(
            f"{NG}/staticMembers/spoke",
            "microsoft.network/networkmanagers/networkgroups/staticmembers",
            {"resourceId": VNET},
        ),
        _row(
            CONN_CFG,
            "microsoft.network/networkmanagers/connectivityconfigurations",
            {
                "connectivityTopology": "HubAndSpoke",
                "hubs": [
                    {"resourceId": HUB_VNET, "resourceType": "Microsoft.Network/virtualNetworks"}
                ],
                "appliesToGroups": [{"networkGroupId": NG, "useHubGateway": "True"}],
            },
        ),
        _row(ADMIN_CFG, "microsoft.network/networkmanagers/securityadminconfigurations"),
        _row(
            RULE_COLL,
            "microsoft.network/networkmanagers/securityadminconfigurations/rulecollections",
            {"appliesToGroups": [{"networkGroupId": NG}]},
        ),
        _row(
            f"{RULE_COLL}/rules/deny-rdp",
            "microsoft.network/networkmanagers/securityadminconfigurations/rulecollections/rules",
            {
                "access": "Deny",
                "direction": "Inbound",
                "priority": 10,
                "protocol": "Tcp",
                "sources": [{"addressPrefix": "Internet"}],
                "destinationPortRanges": ["3389"],
            },
        ),
    ]


def _tables() -> dict[str, list[dict]]:
    return {
        "resources": _resource_rows(),
        "resourcecontainers": [
            {
                "id": SUB_REF,
                "name": "Gov",
                "type": "microsoft.resources/subscriptions",
                "subscriptionId": SUB,
                "properties": {
                    "managementGroupAncestorsChain": [{"name": "corp"}, {"name": "tenant-root"}]
                },
            },
            {
                "id": RG,
                "name": "rg-gov",
                "type": "microsoft.resources/subscriptions/resourcegroups",
                "subscriptionId": SUB,
                "properties": {},
            },
        ],
        "authorizationresources": _authorization_rows(),
        "securityresources": _security_rows(),
        "policyresources": _policy_rows(),
        "recoveryservicesresources": _recovery_rows(),
        "kubernetesconfigurationresources": _k8s_config_rows(),
        "networkresources": _network_rows(),
        "guestconfigurationresources": [
            _row(
                f"{VM}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/AzureBaseline",
                "microsoft.guestconfiguration/guestconfigurationassignments",
                {
                    "complianceStatus": "NonCompliant",
                    "guestConfiguration": {"name": "AzureLinuxBaseline"},
                },
            ),
        ],
        "maintenanceresources": [
            _row(
                f"{VM}/providers/Microsoft.Maintenance/configurationAssignments/weekly",
                "microsoft.maintenance/configurationassignments",
                {"maintenanceConfigurationId": MAINT, "resourceId": VM},
            ),
        ],
        "insightsresources": [
            _row(
                f"{VM}/providers/Microsoft.Insights/dataCollectionRuleAssociations/syslog",
                "microsoft.insights/datacollectionruleassociations",
                {"dataCollectionRuleId": DCR},
            ),
        ],
    }


@pytest.fixture(scope="module")
def mapped():
    return collect_linked(_tables())


# ── policy ──


class TestPolicy:
    def test_assignments_and_definitions(self, mapped):
        g = mapped.graph
        assignment = g.a(ASSIGN_DENY)
        assert assignment.asset_type == AssetType.GUARDRAIL
        assert assignment.metadata["denies"] is True
        assert g.has(ASSIGN_DENY, SUB_REF, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS")
        assert g.has(ASSIGN_DENY, DENY_DEF, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.a(DENY_DEF).asset_type == AssetType.ORG_POLICY
        assert g.a(INITIATIVE).metadata["member_count"] == 2
        assert g.has(INITIATIVE, AUDIT_DEF, EdgeType.REFERENCES, "DEPENDS_ON")

    def test_deny_definition_restricts_enforced_scopes(self, mapped):
        g = mapped.graph
        # the SCP analogue: deny definition -> scope of an enforced assignment
        assert g.has(DENY_DEF, SUB_REF, EdgeType.GOVERNS, "SCP_RESTRICTS")
        # DoNotEnforce assignments restrict nothing
        assert not g.has(DENY_DEF, RG, EdgeType.GOVERNS, "SCP_RESTRICTS")
        # initiatives: a deny member makes the initiative restrict too
        assert g.a(ASSIGN_SET).metadata["denies"] is True
        assert g.has(INITIATIVE, SUB_REF, EdgeType.GOVERNS, "SCP_RESTRICTS")
        assert not g.has(AUDIT_DEF, SUB_REF, EdgeType.GOVERNS, "SCP_RESTRICTS")

    def test_exemption_and_states(self, mapped):
        g = mapped.graph
        assert g.has(EXEMPTION, RG, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS")
        assert g.has(EXEMPTION, ASSIGN_DENY, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.has(ASSIGN_SET, VM, EdgeType.GOVERNS, "FINDING_AFFECTS")
        assert g.a(ASSIGN_SET).metadata["non_compliant_resources"] == 1

    def test_guest_configuration(self, mapped):
        g = mapped.graph
        gc = f"{VM}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/AzureBaseline"
        assert g.a(gc).asset_type == AssetType.GUARDRAIL
        assert g.has(gc, VM, EdgeType.GOVERNS, "FINDING_AFFECTS")


# ── RBAC ──


class TestRbac:
    def test_role_definitions_and_attachments(self, mapped):
        g = mapped.graph
        owner = g.a(f"/providers/Microsoft.Authorization/roleDefinitions/{OWNER_GUID}")
        assert owner.asset_type == AssetType.IAM_POLICY
        assert owner.metadata["privileged"] is True and owner.metadata["actions"] == ["*"]
        custom = g.a(f"{SUB_REF}/providers/Microsoft.Authorization/roleDefinitions/{CUSTOM_GUID}")
        assert custom.metadata["custom"] is True
        user = f"entra:principal/{USER_OID}"
        sp = f"entra:principal/{SP_OID}"
        group = f"entra:principal/{GROUP_OID}"
        assert g.has(user, owner.arn, EdgeType.IAM_POLICY_ATTACHMENT, "USER_HAS_POLICY")
        assert g.has(sp, custom.arn, EdgeType.IAM_POLICY_ATTACHMENT, "ROLE_HAS_POLICY")
        assert g.has(group, owner.arn, EdgeType.IAM_POLICY_ATTACHMENT, "GROUP_HAS_POLICY")
        assert g.has(sp, ST, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION")

    def test_management_group_assignments_are_inherited(self, mapped):
        g = mapped.graph
        group = g.a(f"entra:principal/{GROUP_OID}")
        grants = [r for r in group.metadata["relations"] if r["edge"] == "GRANTS_ACCESS"]
        assert [r["target"] for r in grants] == [MG]
        assert grants[0]["properties"]["inherited_from"] == "management group"
        # an assignment on a management group outside the chain is not inherited
        user = g.a(f"entra:principal/{USER_OID}")
        targets = {r["target"] for r in user.metadata["relations"] if r["edge"] == "GRANTS_ACCESS"}
        assert "/providers/Microsoft.Management/managementGroups/other" not in targets


# ── Defender for Cloud ──


class TestDefender:
    def test_per_resource_plan_coverage(self, mapped):
        g = mapped.graph
        vms = f"{SUB_REF}/providers/Microsoft.Security/pricings/VirtualMachines"
        assert g.has(vms, SUB_REF, EdgeType.MONITORS, "MONITORED_BY")
        assert g.has(vms, VM, EdgeType.MONITORS, "MONITORED_BY")
        # a resource-level Free pricing turns the plan off for that VM
        assert not g.has(vms, VM2, EdgeType.MONITORS)
        storage = g.a(f"{SUB_REF}/providers/Microsoft.Security/pricings/StorageAccounts")
        assert storage.metadata["extensions"][0]["name"] == "OnUploadMalwareScanning"
        assert g.has(storage.arn, ST, EdgeType.MONITORS, "MONITORED_BY")
        # resource-level pricings are overrides, not plan assets of their own
        assert (
            f"{VM2}/providers/Microsoft.Security/pricings/VirtualMachines".lower() not in g.by_arn
        )

    def test_not_enabled_placeholders(self, mapped):
        g = mapped.graph
        kv = g.a(f"cloudg:azure:defender-keyvaults:{SUB}:not-enabled")
        assert kv.asset_type == AssetType.THREAT_DETECTOR
        assert kv.metadata["enabled"] is False and kv.metadata["status"] == "not enabled"
        assert kv.metadata["aliases"] == [f"azure-security:defender-keyvaults:{SUB}"]
        assert f"cloudg:azure:defender-virtualmachines:{SUB}:not-enabled" not in g.by_arn

    def test_assessments_score_and_alerts(self, mapped):
        g = mapped.graph
        cspm = g.a(f"cloudg:azure:defender-cspm:{SUB}")
        assert cspm.asset_type == AssetType.SECURITY_HUB
        assert cspm.metadata["secure_score"]["current"] == 31.5
        assert cspm.metadata["secure_score_controls"][0]["control"] == "Enable MFA"
        assert g.has(cspm.arn, VM, EdgeType.MONITORS, "FINDING_AFFECTS")
        assert g.has(cspm.arn, ST, EdgeType.MONITORS, "MONITORED_BY")
        acr_edge = g.edge(cspm.arn, ACR, EdgeType.MONITORS)
        assert acr_edge.relationship == "FINDING_AFFECTS"
        assert acr_edge.properties["vulnerabilities"] == 1
        assert acr_edge.properties["images"] == ["payments/api"]
        alerts = g.a(f"cloudg:azure:defender-alerts:{SUB}")
        assert alerts.metadata["active_alerts"] == 1
        assert g.edge(alerts.arn, VM, EdgeType.MONITORS).properties["names"] == ["Suspicious login"]


# ── backup, Kubernetes configuration, network manager, ops tables ──


class TestTables:
    def test_backup_items(self, mapped):
        g = mapped.graph
        policy = f"{RSV}/backupPolicies/daily"
        assert g.a(policy).asset_type == AssetType.BACKUP_PLAN
        assert g.has(policy, RSV, EdgeType.REFERENCES, "BACKUP_TO")
        assert g.has(policy, VM, EdgeType.MANAGES, "BACKUP_TO")
        assert g.has(VM, RSV, EdgeType.REFERENCES, "BACKUP_TO")
        assert g.has(ST, BVAULT, EdgeType.REFERENCES, "BACKUP_TO")
        # Site Recovery
        assert g.has(VM, VM2, EdgeType.REFERENCES, "REPLICATES_TO")
        assert g.has(RSV, VM, EdgeType.MANAGES, "REPLICATES_TO")
        vault = g.a(RSV)
        assert vault.metadata["immutability"] == "Locked"
        assert vault.metadata["soft_delete"] == "AlwaysON"
        assert any(r.get("relationship") == "ENCRYPTED_BY_KMS" for r in vault.metadata["relations"])

    def test_kubernetes_configuration(self, mapped):
        g = mapped.graph
        ext = f"{AKS}/providers/Microsoft.KubernetesConfiguration/extensions/flux"
        flux = f"{AKS}/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/apps"
        assert g.a(ext).asset_type == AssetType.CLUSTER_ADDON
        assert g.has(AKS, ext, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE")
        repo = "repo:https://github.com/contoso/gitops"
        assert g.a(repo).asset_type == AssetType.SOURCE_CONNECTION
        assert g.has(flux, repo, EdgeType.REFERENCES, "READS_FROM")
        assert g.has(flux, AKS, EdgeType.MANAGES, "OWNED_BY")

    def test_network_manager(self, mapped):
        g = mapped.graph
        assert g.has(AVNM, SUB_REF, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS")
        assert g.has(NG, VNET, EdgeType.CONTAINS)
        assert g.has(CONN_CFG, HUB_VNET, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.has(CONN_CFG, NG, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.has(RULE_COLL, NG, EdgeType.PROTECTS, "PROTECTED_BY_NACL")
        coll = g.a(RULE_COLL)
        assert coll.metadata["denies"] is True and coll.metadata["rules"][0]["access"] == "Deny"
        # static members are links, not assets
        assert f"{NG}/staticMembers/spoke".lower() not in g.by_arn

    def test_maintenance_and_data_collection(self, mapped):
        g = mapped.graph
        assert g.has(MAINT, VM, EdgeType.MANAGES, "SCHEDULED_BY")
        assert g.has(VM, DCR, EdgeType.LOGS_TO, "LOGS_TO")
        assert g.has(DCR, VM, EdgeType.MONITORS, "MONITORED_BY")
        assert g.has(DCR, LAW, EdgeType.LOGS_TO, "LOGS_TO")


# ── coverage records, failures and service filtering ──


class TestCoverageAndFiltering:
    def test_per_task_coverage(self, mapped):
        cov = mapped.coverage
        for task in (
            "resources",
            "policy",
            "policy_states",
            "security_assessments",
            "backup_items",
            "kubernetes_configuration",
            "network_resources",
            "role_definitions",
            "management_group_role_assignments",
        ):
            assert cov[task].status == ServiceStatus.SUCCESS, task
        assert cov["policy"].asset_count == 7
        assert cov["locks"].status == ServiceStatus.SUCCESS  # nothing listed (404s are "none")

    def test_rest_tasks_skipped_without_token(self):
        from tests.azure_fakes import TypedFakeGraph
        from cloudg.inventory.azure_deep import AzureDeepInventoryCollector

        fake = TypedFakeGraph(_tables())
        # no arm_client_factory: the default REST client asks object() for a token
        collector = AzureDeepInventoryCollector(object(), SUB, graph_client_factory=lambda c: fake)
        asyncio.run(collector.collect())
        cov = {s.service: s for s in collector.coverage.services}
        assert cov["locks"].status == ServiceStatus.SKIPPED
        assert "access tokens" in cov["locks"].error
        assert collector.service_errors == {}

    def test_failed_table_is_recorded_not_fatal(self):
        from tests.azure_fakes import TypedFakeGraph
        from cloudg.inventory.azure_deep import AzureDeepInventoryCollector

        fake = TypedFakeGraph(_tables(), fail={"policyresources", "recoveryservicesresources"})
        collector = AzureDeepInventoryCollector(object(), SUB, graph_client_factory=lambda c: fake)
        assets = asyncio.run(collector.collect())
        cov = {s.service: s for s in collector.coverage.services}
        assert collector.collection_mode == "resource-graph"
        assert cov["policy"].status == ServiceStatus.FAILED
        assert cov["policy_states"].status == ServiceStatus.FAILED
        assert cov["backup_items"].status == ServiceStatus.FAILED
        assert cov["security_assessments"].status == ServiceStatus.SUCCESS
        assert any(a.arn == VM for a in assets)

    def test_services_filter(self):
        out = collect_linked(_tables(), services=["network"])
        arns = {a.arn for a in out.assets}
        assert VNET in arns and VM not in arns and ST not in arns
        assert RG in arns  # resource groups always stay
        assert out.coverage["policy"].status == ServiceStatus.SKIPPED
        assert out.coverage["network_resources"].status == ServiceStatus.SUCCESS
        assert "not selected" in out.coverage["apim"].error

    def test_exclude_services(self):
        out = collect_linked(_tables(), exclude_services=["security", "backup_items"])
        assert out.coverage["security_assessments"].status == ServiceStatus.SKIPPED
        assert out.coverage["backup_items"].status == ServiceStatus.SKIPPED
        assert out.coverage["policy"].status == ServiceStatus.SUCCESS
        assert f"cloudg:azure:defender-cspm:{SUB}" not in {a.arn for a in out.assets}

    def test_select_tasks_mirrors_aws(self):
        assert "resources" in select_azure_tasks(None, ["identity"], None)
        assert "role_assignments" in select_azure_tasks(None, ["identity"], None)
        assert "apim" not in select_azure_tasks(None, ["identity"], None)
        assert select_azure_tasks(["apim", "functions"], ["apim"], None) == ["apim"]
        assert "aks_kubernetes" in select_azure_tasks(None, ["containers"], None)
        assert "aks_kubernetes" not in select_azure_tasks(None, ["all"], ["kubernetes"])
        # core tasks always run, even when excluded
        assert "resources" in select_azure_tasks(None, ["all"], ["sweep"])

    def test_row_filter_by_family(self):
        assert row_filter(None, None) is None
        keep = row_filter(["dns"], None)
        assert keep({"type": "microsoft.network/dnszones"})
        assert not keep({"type": "microsoft.network/virtualnetworks"})
        assert keep({"type": "microsoft.resources/subscriptions/resourcegroups"})
        assert family_of_type("microsoft.network/dnszones/a") == "dns"
        assert family_of_type("microsoft.web/sites") == "serverless"

    def test_recorder_outcome(self):
        cov = CollectionCoverage(provider="azure")
        rec = TaskRecorder(cov)
        rec.outcome("a", 3, [], 2, None)
        rec.outcome("b", 1, ["403"], 2, None)
        rec.outcome("c", 0, ["403", "403"], 2, None)
        assert [s.status for s in cov.services] == [
            ServiceStatus.SUCCESS,
            ServiceStatus.PARTIAL,
            ServiceStatus.FAILED,
        ]


def test_multi_records_task_coverage_and_partial():
    from cloudg.collectors.multi import MultiAccountCollector
    from cloudg.config import CloudGConfig

    class WithCoverage:
        def __init__(self, credential, subscription_id):
            self.service_errors = {}
            self.coverage = CollectionCoverage(provider="azure", account_id=subscription_id)
            self.coverage.record("policy", ServiceStatus.SUCCESS, asset_count=3)
            self.coverage.record("apim", ServiceStatus.FAILED, error="403")

        async def collect(self):
            return [
                CloudAsset(
                    arn=VM,
                    name="vm",
                    asset_type=AssetType.VIRTUAL_MACHINE,
                    provider=CloudProvider.AZURE,
                )
            ]

        async def collect_edges(self):
            return []

    cfg = CloudGConfig(providers=["azure"])
    multi = MultiAccountCollector(cfg, collector_overrides={"azure": WithCoverage})
    asyncio.run(multi._collect_azure_single(SUB, credential=object()))
    services = {s.service: s.status for s in multi._coverage[0].services}
    assert services["policy"] == ServiceStatus.SUCCESS
    assert services["apim"] == ServiceStatus.FAILED
    assert services["azure_full"] == ServiceStatus.PARTIAL
