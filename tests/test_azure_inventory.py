"""Tests for the Azure inventory mapper (Resource Graph + SDK fallback)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from cloudg.collectors.azure import AzureCollector
from cloudg.inventory.azure_deep import AzureDeepInventoryCollector, asset_type_from_arm
from cloudg.inventory.azure_graph import (
    AzureAssetBuilder,
    owner_resource_id,
    parent_resource_id,
    run_query,
)
from cloudg.inventory.azure_hierarchy import alz_archetype, discover_azure_hierarchy
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

SUB = "11111111-1111-1111-1111-111111111111"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-app"
HUB_RG = f"/subscriptions/{SUB}/resourceGroups/rg-hub"
MC_RG = f"/subscriptions/{SUB}/resourceGroups/MC_rg-app_aks-prod_eastus"
NET = f"{RG}/providers/Microsoft.Network"
VNET = f"{NET}/virtualNetworks/vnet-app"
SNET_AKS = f"{VNET}/subnets/snet-aks"
SNET_PE = f"{VNET}/subnets/snet-pe"
SNET_WEB = f"{VNET}/subnets/snet-web"
HUB_VNET = f"{HUB_RG}/providers/Microsoft.Network/virtualNetworks/vnet-hub"
FW_SUBNET = f"{HUB_VNET}/subnets/AzureFirewallSubnet"
NSG = f"{NET}/networkSecurityGroups/nsg-aks"
ASG = f"{NET}/applicationSecurityGroups/asg-web"
RT = f"{NET}/routeTables/rt-app"
FW = f"{HUB_RG}/providers/Microsoft.Network/azureFirewalls/fw-hub"
PIP_FW = f"{HUB_RG}/providers/Microsoft.Network/publicIPAddresses/pip-fw"
PIP_VM = f"{NET}/publicIPAddresses/pip-vm"
NIC = f"{NET}/networkInterfaces/nic-vm"
LB = f"{NET}/loadBalancers/lb-int"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-1"
VMSS = f"{RG}/providers/Microsoft.Compute/virtualMachineScaleSets/vmss-1"
DISK = f"{RG}/providers/Microsoft.Compute/disks/vm-1-os"
DES = f"{RG}/providers/Microsoft.Compute/diskEncryptionSets/des-1"
KV = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-app"
ST = f"{RG}/providers/Microsoft.Storage/storageAccounts/stapp"
PE = f"{NET}/privateEndpoints/pe-stapp"
AKS = f"{RG}/providers/Microsoft.ContainerService/managedClusters/aks-prod"
UAMI_KUBELET = f"{MC_RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-prod-agentpool"
UAMI_APP = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-web"
ACR = f"{RG}/providers/Microsoft.ContainerRegistry/registries/acrprod"
LAW = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-app"
PLAN = f"{RG}/providers/Microsoft.Web/serverfarms/plan-app"
WEB = f"{RG}/providers/Microsoft.Web/sites/web-app"
FUNC = f"{RG}/providers/Microsoft.Web/sites/func-app"
APPGW = f"{NET}/applicationGateways/agw-app"
WAF = f"{NET}/ApplicationGatewayWebApplicationFirewallPolicies/waf-app"

VM_PRINCIPAL = "aaaaaaaa-0000-0000-0000-000000000001"
KUBELET_OID = "cccccccc-0000-0000-0000-000000000003"
UNKNOWN_OID = "bbbbbbbb-0000-0000-0000-000000000002"
USER_OID = "dddddddd-0000-0000-0000-000000000004"
WEB_UAMI_OID = "eeeeeeee-0000-0000-0000-000000000005"


def _row(rid, rtype, properties=None, **extra):
    row = {
        "id": rid,
        "name": rid.rsplit("/", 1)[-1],
        "type": rtype,
        "location": "eastus",
        "subscriptionId": SUB,
        "resourceGroup": rid.split("/")[4].lower(),
        "tags": {},
        "properties": properties or {},
    }
    row.update(extra)
    return row


def _resource_rows():
    return [
        _row(
            VNET,
            "microsoft.network/virtualnetworks",
            {
                "addressSpace": {"addressPrefixes": ["10.1.0.0/16"]},
                "subnets": [
                    {
                        "id": SNET_AKS,
                        "name": "snet-aks",
                        "properties": {
                            "addressPrefix": None,
                            "addressPrefixes": ["10.1.0.0/24", "10.1.1.0/24"],
                            "networkSecurityGroup": {"id": NSG},
                            "routeTable": {"id": RT},
                            "serviceEndpoints": [{"service": "Microsoft.Storage"}],
                            "ipConfigurations": [{"id": f"{NIC}/ipConfigurations/ipconfig1"}],
                        },
                    },
                    {
                        "id": SNET_PE,
                        "name": "snet-pe",
                        "properties": {"addressPrefix": "10.1.2.0/24", "privateEndpoints": [{"id": PE}]},
                    },
                    {
                        "id": SNET_WEB,
                        "name": "snet-web",
                        "properties": {
                            "addressPrefix": "10.1.3.0/24",
                            "delegations": [{"name": "d", "properties": {"serviceName": "Microsoft.Web/serverFarms"}}],
                        },
                    },
                ],
                "virtualNetworkPeerings": [
                    {
                        "name": "to-hub",
                        "properties": {"remoteVirtualNetwork": {"id": HUB_VNET}, "peeringState": "Connected"},
                    }
                ],
            },
        ),
        _row(
            HUB_VNET,
            "microsoft.network/virtualnetworks",
            {
                "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                "subnets": [{"id": FW_SUBNET, "name": "AzureFirewallSubnet", "properties": {"addressPrefix": "10.0.0.0/26"}}],
            },
        ),
        _row(
            NSG,
            "microsoft.network/networksecuritygroups",
            {
                "securityRules": [
                    {
                        "name": "allow-partners",
                        "properties": {
                            "priority": 100,
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "sourceAddressPrefix": None,
                            "sourceAddressPrefixes": ["203.0.113.0/24", "198.51.100.0/24"],
                            "destinationPortRange": None,
                            "destinationPortRanges": ["443", "8443"],
                        },
                    },
                    {
                        "name": "allow-asg",
                        "properties": {
                            "priority": 110,
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "*",
                            "sourceApplicationSecurityGroups": [{"id": ASG}],
                            "destinationPortRange": "22",
                        },
                    },
                ],
                "defaultSecurityRules": [
                    {
                        "name": "AllowVnetInBound",
                        "properties": {
                            "priority": 65000,
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "*",
                            "sourceAddressPrefix": "VirtualNetwork",
                            "destinationPortRange": "*",
                        },
                    }
                ],
            },
        ),
        _row(ASG, "microsoft.network/applicationsecuritygroups"),
        _row(
            RT,
            "microsoft.network/routetables",
            {
                "routes": [
                    {
                        "name": "default-via-fw",
                        "properties": {
                            "addressPrefix": "0.0.0.0/0",
                            "nextHopType": "VirtualAppliance",
                            "nextHopIpAddress": "10.0.0.4",
                        },
                    }
                ],
                "subnets": [{"id": SNET_AKS}],
            },
        ),
        _row(
            FW,
            "microsoft.network/azurefirewalls",
            {
                "ipConfigurations": [
                    {
                        "id": f"{FW}/azureFirewallIpConfigurations/ipc",
                        "name": "ipc",
                        "properties": {
                            "privateIPAddress": "10.0.0.4",
                            "subnet": {"id": FW_SUBNET},
                            "publicIPAddress": {"id": PIP_FW},
                        },
                    }
                ]
            },
        ),
        _row(
            PIP_FW,
            "microsoft.network/publicipaddresses",
            {"ipAddress": "20.1.2.3", "ipConfiguration": {"id": f"{FW}/azureFirewallIpConfigurations/ipc"}},
        ),
        _row(
            PIP_VM,
            "microsoft.network/publicipaddresses",
            {"ipAddress": "20.1.2.4", "ipConfiguration": {"id": f"{NIC}/ipConfigurations/ipconfig1"}},
        ),
        _row(
            NIC,
            "microsoft.network/networkinterfaces",
            {
                "ipConfigurations": [
                    {
                        "id": f"{NIC}/ipConfigurations/ipconfig1",
                        "name": "ipconfig1",
                        "properties": {
                            "privateIPAddress": "10.1.0.5",
                            "subnet": {"id": SNET_AKS},
                            "publicIPAddress": {"id": PIP_VM},
                            "applicationSecurityGroups": [{"id": ASG}],
                        },
                    },
                    {
                        "id": f"{NIC}/ipConfigurations/ipconfig2",
                        "name": "ipconfig2",
                        "properties": {
                            "privateIPAddress": "10.1.0.6",
                            "subnet": {"id": SNET_AKS},
                            "loadBalancerBackendAddressPools": [{"id": f"{LB}/backendAddressPools/pool"}],
                        },
                    },
                ],
                "networkSecurityGroup": {"id": NSG},
                "virtualMachine": {"id": VM},
            },
        ),
        _row(
            LB,
            "microsoft.network/loadbalancers",
            {
                "frontendIPConfigurations": [
                    {
                        "id": f"{LB}/frontendIPConfigurations/fe",
                        "properties": {"privateIPAddress": "10.1.0.100", "subnet": {"id": SNET_AKS}},
                    }
                ],
                "backendAddressPools": [
                    {
                        "id": f"{LB}/backendAddressPools/pool",
                        "name": "pool",
                        "properties": {
                            "backendIPConfigurations": [
                                {"id": f"{NIC}/ipConfigurations/ipconfig2"},
                                {
                                    "id": f"{VMSS}/virtualMachines/0/networkInterfaces/nic/ipConfigurations/ipc"
                                },
                            ],
                            "loadBalancerBackendAddresses": [
                                {"name": "a1", "properties": {"ipAddress": "10.0.0.4"}}
                            ],
                        },
                    }
                ],
            },
            sku={"name": "Standard"},
        ),
        _row(VMSS, "microsoft.compute/virtualmachinescalesets"),
        _row(
            VM,
            "microsoft.compute/virtualmachines",
            {
                "hardwareProfile": {"vmSize": "Standard_D2s_v5"},
                "storageProfile": {"osDisk": {"osType": "Linux", "managedDisk": {"id": DISK}}},
                "networkProfile": {"networkInterfaces": [{"id": NIC}]},
            },
            identity={"type": "SystemAssigned", "principalId": VM_PRINCIPAL},
        ),
        _row(
            DISK,
            "microsoft.compute/disks",
            {"diskSizeGB": 64, "encryption": {"type": "EncryptionAtRestWithCustomerKey", "diskEncryptionSetId": DES}},
            managedBy=VM,
        ),
        _row(DES, "microsoft.compute/diskencryptionsets", {"activeKey": {"sourceVault": {"id": KV},
                                                                          "keyUrl": "https://kv-app.vault.azure.net/keys/k/1"}}),
        _row(
            KV,
            "microsoft.keyvault/vaults",
            {
                "vaultUri": "https://kv-app.vault.azure.net/",
                "enableRbacAuthorization": False,
                "accessPolicies": [
                    {"objectId": VM_PRINCIPAL, "permissions": {"secrets": ["get"]}},
                    {"objectId": UNKNOWN_OID, "permissions": {"keys": ["get", "wrapKey"]}},
                ],
                "networkAcls": {"defaultAction": "Allow", "virtualNetworkRules": [{"id": SNET_AKS}]},
                "publicNetworkAccess": "Enabled",
            },
        ),
        _row(
            ST,
            "microsoft.storage/storageaccounts",
            {
                "publicNetworkAccess": "Enabled",
                "allowBlobPublicAccess": False,
                "networkAcls": {"defaultAction": "Deny"},
                "primaryEndpoints": {"blob": "https://stapp.blob.core.windows.net/"},
                "encryption": {
                    "keySource": "Microsoft.Keyvault",
                    "keyvaultproperties": {"keyvaulturi": "https://kv-app.vault.azure.net"},
                },
            },
            kind="StorageV2",
            sku={"name": "Standard_LRS"},
        ),
        _row(
            PE,
            "microsoft.network/privateendpoints",
            {
                "subnet": {"id": SNET_PE},
                "privateLinkServiceConnections": [
                    {"name": "c", "properties": {"privateLinkServiceId": ST, "groupIds": ["blob"]}}
                ],
            },
        ),
        _row(
            AKS,
            "microsoft.containerservice/managedclusters",
            {
                "kubernetesVersion": "1.30.3",
                "fqdn": "aks-prod-dns.hcp.eastus.azmk8s.io",
                "nodeResourceGroup": "MC_rg-app_aks-prod_eastus",
                "identityProfile": {
                    "kubeletidentity": {"resourceId": UAMI_KUBELET, "objectId": KUBELET_OID, "clientId": "c1"}
                },
                "agentPoolProfiles": [
                    {"name": "system", "count": 3, "vmSize": "Standard_D4s_v5", "mode": "System",
                     "vnetSubnetID": SNET_AKS}
                ],
                "addonProfiles": {"omsagent": {"enabled": True, "config": {"logAnalyticsWorkspaceResourceID": LAW}}},
                "apiServerAccessProfile": {"enablePrivateCluster": False},
            },
            identity={"type": "SystemAssigned", "principalId": "ffffffff-0000-0000-0000-000000000006"},
        ),
        _row(
            UAMI_KUBELET,
            "microsoft.managedidentity/userassignedidentities",
            {"principalId": KUBELET_OID, "clientId": "c1"},
        ),
        _row(UAMI_APP, "microsoft.managedidentity/userassignedidentities", {"principalId": WEB_UAMI_OID}),
        _row(ACR, "microsoft.containerregistry/registries", {"loginServer": "acrprod.azurecr.io",
                                                               "publicNetworkAccess": "Enabled"}),
        _row(LAW, "microsoft.operationalinsights/workspaces", {"customerId": "law-customer-guid"}),
        _row(PLAN, "microsoft.web/serverfarms", {"numberOfSites": 2}, kind="linux", sku={"name": "P1v3", "tier": "PremiumV3"}),
        _row(
            WEB,
            "microsoft.web/sites",
            {
                "serverFarmId": PLAN,
                "virtualNetworkSubnetId": SNET_WEB,
                "defaultHostName": "web-app.azurewebsites.net",
                "siteConfig": {"linuxFxVersion": "DOCKER|acrprod.azurecr.io/web:1.0"},
                "keyVaultReferenceIdentity": UAMI_APP,
            },
            kind="app,linux,container",
            identity={"type": "UserAssigned", "userAssignedIdentities": {UAMI_APP: {"principalId": WEB_UAMI_OID}}},
        ),
        _row(
            FUNC,
            "microsoft.web/sites",
            {
                "serverFarmId": PLAN,
                "siteProperties": {"properties": [{"name": "LinuxFxVersion", "value": "Python|3.11"}]},
                "defaultHostName": "func-app.azurewebsites.net",
            },
            kind="functionapp,linux",
        ),
        _row(
            APPGW,
            "microsoft.network/applicationgateways",
            {
                "gatewayIPConfigurations": [{"properties": {"subnet": {"id": SNET_WEB}}}],
                "frontendIPConfigurations": [{"id": f"{APPGW}/frontendIPConfigurations/fe",
                                              "properties": {"publicIPAddress": {"id": PIP_FW}}}],
                "backendAddressPools": [
                    {"name": "web", "properties": {"backendAddresses": [{"fqdn": "web-app.azurewebsites.net"}]}}
                ],
                "firewallPolicy": {"id": WAF},
            },
        ),
        _row(WAF, "microsoft.network/applicationgatewaywebapplicationfirewallpolicies"),
    ]


def _container_rows():
    return [
        {"id": f"/subscriptions/{SUB}", "name": "Production", "type": "microsoft.resources/subscriptions",
         "subscriptionId": SUB, "properties": {"state": "Enabled"}},
        {"id": RG, "name": "rg-app", "type": "microsoft.resources/subscriptions/resourcegroups",
         "location": "eastus", "subscriptionId": SUB, "properties": {}},
        {"id": HUB_RG, "name": "rg-hub", "type": "microsoft.resources/subscriptions/resourcegroups",
         "location": "eastus", "subscriptionId": SUB, "properties": {}},
        {"id": MC_RG, "name": "MC_rg-app_aks-prod_eastus", "type": "microsoft.resources/subscriptions/resourcegroups",
         "location": "eastus", "subscriptionId": SUB, "managedBy": AKS, "properties": {}},
    ]


def _role_rows():
    return [
        {
            "id": f"{ACR}/providers/Microsoft.Authorization/roleAssignments/ra1",
            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/"
            "7f951dda-4ed3-4680-a7ca-43fe172d538d",
            "roleGuid": "7f951dda-4ed3-4680-a7ca-43fe172d538d",
            "roleName": "AcrPull",
            "principalId": KUBELET_OID,
            "principalType": "ServicePrincipal",
            "scope": ACR,
            "properties": {},
        },
        {
            "id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/ra2",
            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/"
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
            "roleName": None,
            "principalId": USER_OID,
            "principalType": "User",
            "scope": f"/subscriptions/{SUB}",
            "properties": {},
        },
    ]


def _pricing_rows():
    return [
        {"id": f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/VirtualMachines",
         "name": "VirtualMachines", "properties": {"pricingTier": "Standard", "subPlan": "P2"}},
        {"id": f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/StorageAccounts",
         "name": "StorageAccounts", "properties": {"pricingTier": "Free"}},
    ]


class FakeGraph:
    """Resource Graph stand-in dispatching on the KQL table name."""

    def __init__(self, tables, page_size=10):
        self.tables = tables
        self.page_size = page_size
        self.requests = []

    def resources(self, request):
        self.requests.append(request)
        query = request.query.strip()
        table = query.split("|", 1)[0].strip()
        rows = self.tables.get(table, [])
        start = int(request.options.skip_token or 0)
        page = rows[start: start + self.page_size]
        nxt = start + self.page_size
        return SimpleNamespace(data=page, skip_token=str(nxt) if nxt < len(rows) else None)


def _graph_tables():
    return {
        "resources": _resource_rows(),
        "resourcecontainers": _container_rows(),
        "authorizationresources": _role_rows(),
        "securityresources": _pricing_rows(),
    }


def _run(coro):
    return asyncio.run(coro)


def _link(assets):
    linker = RelationshipLinker(assets)
    edges = linker.link()
    return edges, linker


class _Graph:
    def __init__(self, assets, edges):
        self.assets = assets
        self.edges = edges
        self.by_arn = {a.arn.lower(): a for a in assets if a.arn}

    def a(self, arn):
        return self.by_arn[arn.lower()]

    def has(self, src, dst, edge_type, relationship=None):
        s, t = self.a(src).id, self.a(dst).id
        return any(
            e.source_id == s and e.target_id == t and e.edge_type == edge_type
            and (relationship is None or e.relationship == relationship)
            for e in self.edges
        )

    def edge(self, src, dst, edge_type):
        s, t = self.a(src).id, self.a(dst).id
        return next(e for e in self.edges if e.source_id == s and e.target_id == t and e.edge_type == edge_type)


@pytest.fixture(scope="module")
def graph_inventory():
    fake = FakeGraph(_graph_tables())
    collector = AzureDeepInventoryCollector(object(), SUB, graph_client_factory=lambda cred: fake)
    assets = _run(collector.collect())
    collector_edges = _run(collector.collect_edges())
    linker = RelationshipLinker(assets)
    linker.seed_existing(collector_edges)
    edges = collector_edges + linker.link()
    return SimpleNamespace(collector=collector, fake=fake, graph=_Graph(assets + linker.external_assets, edges),
                           assets=assets, linker=linker)


# ── classification and id helpers ──


class TestHelpers:
    def test_function_app_kind(self):
        assert asset_type_from_arm("Microsoft.Web/sites", "functionapp,linux") == AssetType.CLOUD_FUNCTION
        assert asset_type_from_arm("Microsoft.Web/sites", "app,linux") == AssetType.APP_SERVICE
        assert asset_type_from_arm("Microsoft.Web/serverFarms") == AssetType.APP_SERVICE
        assert asset_type_from_arm("Microsoft.Security/automations") == AssetType.EVENT_RULE
        assert asset_type_from_arm("Microsoft.Resources/subscriptions/resourceGroups") == AssetType.RESOURCE_GROUP

    def test_parent_and_owner_ids(self):
        assert parent_resource_id(SNET_AKS) == VNET
        assert parent_resource_id(VNET) is None
        ext = f"{VM}/providers/Microsoft.Insights/diagnosticSettings/d1"
        assert parent_resource_id(ext) == VM
        assert owner_resource_id(f"{NIC}/ipConfigurations/ipconfig1") == NIC
        assert owner_resource_id(f"{VMSS}/virtualMachines/0/networkInterfaces/n/ipConfigurations/i") == VMSS

    def test_run_query_paginates_and_retries(self):
        class Throttle(Exception):
            status_code = 429

        fake = FakeGraph({"resources": [{"id": str(i)} for i in range(25)]}, page_size=10)
        calls = {"n": 0}
        original = fake.resources

        def flaky(request):
            calls["n"] += 1
            if calls["n"] == 2:
                raise Throttle()
            return original(request)

        fake.resources = flaky
        rows = run_query(fake, "resources | project id", subscriptions=[SUB], sleep=lambda s: None)
        assert [r["id"] for r in rows] == [str(i) for i in range(25)]
        assert calls["n"] == 4  # 3 pages + 1 throttled retry


# ── Resource Graph path ──


class TestResourceGraphInventory:
    def test_mode_and_queries(self, graph_inventory):
        assert graph_inventory.collector.collection_mode == "resource-graph"
        tables = {r.query.split("|", 1)[0].strip() for r in graph_inventory.fake.requests}
        assert tables == {"resources", "resourcecontainers", "authorizationresources", "securityresources"}
        assert all(r.subscriptions == [SUB] for r in graph_inventory.fake.requests)
        assert graph_inventory.collector.service_errors == {}

    def test_asset_types_and_metadata(self, graph_inventory):
        g = graph_inventory.graph
        assert g.a(FUNC).asset_type == AssetType.CLOUD_FUNCTION
        assert g.a(WEB).asset_type == AssetType.APP_SERVICE
        assert g.a(PLAN).metadata["role"] == "plan"
        assert g.a(f"/subscriptions/{SUB}").asset_type == AssetType.CLOUD_ACCOUNT
        assert g.a(f"/subscriptions/{SUB}").name == "Production"
        assert g.a(RG).asset_type == AssetType.RESOURCE_GROUP
        sn = g.a(SNET_AKS)
        assert sn.asset_type == AssetType.SUBNET
        assert sn.metadata["address_prefix"] == "10.1.0.0/24"
        assert sn.metadata["address_prefixes"] == ["10.1.0.0/24", "10.1.1.0/24"]
        assert g.a(SNET_WEB).metadata["delegations"] == ["Microsoft.Web/serverFarms"]
        nic = g.a(NIC).metadata
        assert nic["subnet_id"] == SNET_AKS and nic["attached_instance_id"] == VM
        assert nic["public_ip_id"] == PIP_VM and nic["private_ips"] == ["10.1.0.5", "10.1.0.6"]
        assert g.a(VM).metadata["network_interfaces"] == [NIC]
        assert g.a(KV).metadata["vault_uri"] == "https://kv-app.vault.azure.net/"
        assert "properties" in g.a(ST).metadata

    def test_network_edges(self, graph_inventory):
        g = graph_inventory.graph
        assert g.has(VNET, SNET_AKS, EdgeType.CONTAINS)
        assert g.has(VNET, HUB_VNET, EdgeType.PEERING, "VPC_PEERED")
        assert g.has(SNET_AKS, NSG, EdgeType.ATTACHED_TO)
        assert g.has(RT, SNET_AKS, EdgeType.ATTACHED_TO)
        assert g.has(RT, FW, EdgeType.ROUTE, "TRANSIT_ROUTED")  # next hop IP -> firewall
        assert g.has(SNET_AKS, NIC, EdgeType.CONTAINS)
        assert g.has(NIC, VM, EdgeType.ATTACHED_TO)
        assert g.has(NIC, NSG, EdgeType.ATTACHED_TO)
        assert g.has(NIC, ASG, EdgeType.ATTACHED_TO)
        assert g.has(PIP_VM, NIC, EdgeType.ATTACHED_TO)
        assert g.has(PIP_FW, FW, EdgeType.ATTACHED_TO)
        assert g.has(FW_SUBNET, FW, EdgeType.CONTAINS)
        assert g.has(LB, NIC, EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE")
        assert g.has(LB, VMSS, EdgeType.LOAD_BALANCER_TARGET)
        assert g.has(LB, FW, EdgeType.LOAD_BALANCER_TARGET)  # IP-based backend
        assert g.a(PIP_VM).is_internet_exposed

    def test_compute_and_encryption(self, graph_inventory):
        g = graph_inventory.graph
        assert g.has(DISK, VM, EdgeType.ATTACHED_TO)
        assert g.has(DISK, DES, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        assert g.has(DES, KV, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        assert g.has(ST, KV, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")  # via vault host alias

    def test_aks(self, graph_inventory):
        g = graph_inventory.graph
        pool = f"{AKS}/agentPools/system"
        assert g.a(pool).asset_type == AssetType.NODE_GROUP
        assert g.has(AKS, pool, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE")
        assert g.has(SNET_AKS, pool, EdgeType.CONTAINS)
        assert g.has(AKS, UAMI_KUBELET, EdgeType.ASSUMES_ROLE)
        assert g.has(AKS, LAW, EdgeType.LOGS_TO)
        assert g.has(AKS, MC_RG, EdgeType.MANAGES)
        assert g.has(AKS, ACR, EdgeType.USES_IMAGE)  # AcrPull on the kubelet identity
        assert g.has(UAMI_KUBELET, ACR, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION")
        assert g.edge(UAMI_KUBELET, ACR, EdgeType.GRANTS_ACCESS).properties["role"] == "AcrPull"
        assert g.a(AKS).is_internet_exposed

    def test_app_service(self, graph_inventory):
        g = graph_inventory.graph
        assert g.has(PLAN, WEB, EdgeType.CONTAINS)
        assert g.has(PLAN, FUNC, EdgeType.CONTAINS)
        assert g.has(WEB, SNET_WEB, EdgeType.ATTACHED_TO)
        assert g.has(WEB, ACR, EdgeType.USES_IMAGE, "RUNS_ON")
        assert g.has(WEB, UAMI_APP, EdgeType.ASSUMES_ROLE)
        assert g.has(APPGW, WEB, EdgeType.LOAD_BALANCER_TARGET)  # backend fqdn -> default host
        assert g.has(WAF, APPGW, EdgeType.PROTECTS, "PROTECTED_BY_WAF")
        assert g.has(SNET_WEB, APPGW, EdgeType.CONTAINS)

    def test_private_endpoint_and_exposure(self, graph_inventory):
        g = graph_inventory.graph
        assert g.has(PE, ST, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.has(SNET_PE, PE, EdgeType.CONTAINS)
        assert not g.a(ST).is_internet_exposed  # default-deny ACL
        assert g.a(KV).is_internet_exposed  # public + default Allow
        assert g.a(ACR).is_internet_exposed

    def test_key_vault_access(self, graph_inventory):
        g = graph_inventory.graph
        assert g.has(VM, KV, EdgeType.GRANTS_ACCESS)  # system identity resolves via alias
        unknown = g.a(f"entra:principal/{UNKNOWN_OID}")
        assert unknown.metadata["placeholder"] is True
        assert g.has(f"entra:principal/{UNKNOWN_OID}", KV, EdgeType.GRANTS_ACCESS)
        assert g.has(SNET_AKS, KV, EdgeType.GRANTS_ACCESS)  # VNet rule

    def test_role_assignment_placeholder(self, graph_inventory):
        g = graph_inventory.graph
        user = g.a(f"entra:principal/{USER_OID}")
        assert user.asset_type == AssetType.IDENTITY_USER
        assert USER_OID in user.name
        edge = g.edge(f"entra:principal/{USER_OID}", f"/subscriptions/{SUB}", EdgeType.GRANTS_ACCESS)
        assert edge.properties["role"] == "Owner" and edge.properties["privileged"] is True
        # principals owned by collected resources get no placeholder
        assert f"entra:principal/{KUBELET_OID}" not in g.by_arn

    def test_defender_and_containment(self, graph_inventory):
        g = graph_inventory.graph
        vms = g.a(f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/VirtualMachines")
        assert vms.asset_type == AssetType.THREAT_DETECTOR
        assert vms.metadata["security_service"] == "defender-virtualmachines" and vms.metadata["enabled"]
        assert g.has(vms.arn, f"/subscriptions/{SUB}", EdgeType.MONITORS)
        storage = g.a(f"/subscriptions/{SUB}/providers/Microsoft.Security/pricings/StorageAccounts")
        assert storage.metadata["enabled"] is False
        assert not g.has(storage.arn, f"/subscriptions/{SUB}", EdgeType.MONITORS)
        assert g.has(f"/subscriptions/{SUB}", RG, EdgeType.CONTAINS)
        assert g.has(RG, VNET, EdgeType.CONTAINS)
        assert g.has(MC_RG, UAMI_KUBELET, EdgeType.CONTAINS)

    def test_nsg_rules_with_plural_prefixes(self, graph_inventory):
        g = graph_inventory.graph
        nsg = g.a(NSG)
        rules = {r["name"]: r for r in nsg.metadata["ingress_rules"]}
        assert rules["allow-partners"]["source_address_prefixes"] == ["203.0.113.0/24", "198.51.100.0/24"]
        assert rules["AllowVnetInBound"]["default"] is True
        sg_edges = [e for e in g.edges if e.edge_type == EdgeType.SECURITY_GROUP_RULE and e.target_id == nsg.id]
        sources = {e.source_id for e in sg_edges}
        assert {"203.0.113.0/24", "198.51.100.0/24", "VirtualNetwork", g.a(ASG).id} <= sources
        assert all(e.source_id for e in sg_edges)
        assert any(e.port_range == "443,8443" for e in sg_edges)


# ── NSG regression on the base collector ──


class TestNsgNoneRegression:
    def test_none_source_prefix_does_not_crash(self):
        nsg = CloudAsset(
            arn=NSG,
            name="nsg",
            asset_type=AssetType.NSG,
            provider=CloudProvider.AZURE,
            metadata={
                "ingress_rules": [
                    {"name": "r", "access": "Allow", "direction": "Inbound", "protocol": "Tcp",
                     "source_address_prefix": None, "destination_port_range": None},
                    {"name": "plural", "access": "Allow", "direction": "Inbound", "protocol": None,
                     "source_address_prefix": None, "source_address_prefixes": ["10.0.0.0/8"],
                     "destination_port_ranges": ["80", "443"]},
                ]
            },
        )
        collector = AzureCollector(object(), SUB)
        collector._cached_assets = [nsg]
        edges = _run(collector.collect_edges())
        assert [e.source_id for e in edges] == ["*", "10.0.0.0/8"]
        assert edges[1].port_range == "80,443" and edges[1].protocol == "ALL"


# ── SDK fallback path ──


def _fake_sdk_clients(fail_storage=False):
    from azure.mgmt.keyvault import models as kvm
    from azure.mgmt.network import models as nm
    from azure.mgmt.resource.resources import models as rm
    from azure.mgmt.sql import models as sqlm

    vnet = nm.VirtualNetwork(
        {
            "id": VNET,
            "name": "vnet-app",
            "type": "Microsoft.Network/virtualNetworks",
            "location": "eastus",
            "properties": {
                "addressSpace": {"addressPrefixes": ["10.1.0.0/16"]},
                "subnets": [{"id": SNET_AKS, "name": "snet-aks",
                             "properties": {"addressPrefixes": ["10.1.0.0/24", "10.1.1.0/24"],
                                            "networkSecurityGroup": {"id": NSG}}}],
            },
        }
    )
    nsg = nm.NetworkSecurityGroup(
        {
            "id": NSG,
            "name": "nsg-aks",
            "type": "Microsoft.Network/networkSecurityGroups",
            "location": "eastus",
            "properties": {
                "securityRules": [
                    {"name": "plural", "properties": {"access": "Allow", "direction": "Inbound", "protocol": "Tcp",
                                                      "priority": 100,
                                                      "sourceAddressPrefixes": ["203.0.113.0/24"],
                                                      "destinationPortRanges": ["443"]}}
                ]
            },
        }
    )
    vault = kvm.Vault(
        {
            "id": KV,
            "name": "kv-app",
            "type": "Microsoft.KeyVault/vaults",
            "location": "eastus",
            "properties": {
                "tenantId": "t",
                "sku": {"family": "A", "name": "standard"},
                "vaultUri": "https://kv-app.vault.azure.net/",
                "enableRbacAuthorization": True,
                "accessPolicies": [],
                "networkAcls": {"defaultAction": "Deny"},
                "publicNetworkAccess": "Enabled",
            },
        }
    )
    server_id = f"{RG}/providers/Microsoft.Sql/servers/sql-app"
    server = sqlm.Server({"id": server_id, "name": "sql-app", "type": "Microsoft.Sql/servers", "location": "eastus",
                          "properties": {"fullyQualifiedDomainName": "sql-app.database.windows.net",
                                         "publicNetworkAccess": "Enabled"}})
    fw_rules = [
        sqlm.FirewallRule({"id": f"{server_id}/firewallRules/azure", "name": "AllowAllWindowsAzureIps",
                           "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}),
        sqlm.FirewallRule({"id": f"{server_id}/firewallRules/office", "name": "office",
                           "properties": {"startIpAddress": "198.51.100.1", "endIpAddress": "198.51.100.20"}}),
    ]
    dbs = [
        sqlm.Database({"id": f"{server_id}/databases/master", "name": "master", "location": "eastus",
                       "type": "Microsoft.Sql/servers/databases"}),
        sqlm.Database({"id": f"{server_id}/databases/appdb", "name": "appdb", "location": "eastus",
                       "type": "Microsoft.Sql/servers/databases", "sku": {"name": "S0", "tier": "Standard"},
                       "properties": {"status": "Online"}}),
    ]
    sweep = [
        rm.GenericResourceExpanded({"id": KV, "name": "kv-app", "type": "Microsoft.KeyVault/vaults",
                                    "location": "eastus"}),
        rm.GenericResourceExpanded({"id": WEB, "name": "web-app", "type": "Microsoft.Web/sites",
                                    "kind": "functionapp", "location": "eastus",
                                    "identity": {"type": "SystemAssigned", "principalId": VM_PRINCIPAL}}),
    ]
    groups = [rm.ResourceGroup({"id": RG, "name": "rg-app", "location": "eastus"})]

    def boom():
        raise RuntimeError("storage API unavailable")

    def lister(items):
        return lambda *a, **k: list(items)

    return {
        "network": SimpleNamespace(
            virtual_networks=SimpleNamespace(list_all=lister([vnet])),
            network_security_groups=SimpleNamespace(list_all=lister([nsg])),
            network_interfaces=SimpleNamespace(list_all=lister([])),
            public_ip_addresses=SimpleNamespace(list_all=lister([])),
            load_balancers=SimpleNamespace(list_all=lister([])),
            route_tables=SimpleNamespace(list_all=lister([])),
            nat_gateways=SimpleNamespace(list_all=lister([])),
            private_endpoints=SimpleNamespace(list_by_subscription=lister([])),
            application_gateways=SimpleNamespace(list_all=lister([])),
            azure_firewalls=SimpleNamespace(list_all=lister([])),
        ),
        "compute": SimpleNamespace(
            virtual_machines=SimpleNamespace(list_all=lister([])),
            disks=SimpleNamespace(list=lister([])),
            virtual_machine_scale_sets=SimpleNamespace(list_all=lister([])),
            disk_encryption_sets=SimpleNamespace(list=lister([])),
        ),
        "storage": SimpleNamespace(storage_accounts=SimpleNamespace(list=boom if fail_storage else lister([]))),
        "sql": SimpleNamespace(
            servers=SimpleNamespace(list=lister([server])),
            firewall_rules=SimpleNamespace(list_by_server=lister(fw_rules)),
            virtual_network_rules=SimpleNamespace(list_by_server=lister([])),
            databases=SimpleNamespace(list_by_server=lister(dbs)),
        ),
        "keyvault": SimpleNamespace(
            vaults=SimpleNamespace(list_by_subscription=lister([vault]), list=boom)
        ),
        "resource": SimpleNamespace(
            resources=SimpleNamespace(list=lister(sweep)),
            resource_groups=SimpleNamespace(list=lister(groups)),
        ),
    }


def _no_graph(cred):
    raise ImportError("azure-mgmt-resourcegraph not installed")


class TestSdkFallback:
    def _collect(self, fail_storage=False):
        clients = _fake_sdk_clients(fail_storage=fail_storage)
        collector = AzureDeepInventoryCollector(object(), SUB, graph_client_factory=_no_graph)
        collector._client = lambda kind: clients[kind]
        assets = _run(collector.collect())
        return collector, assets

    def test_fallback_builds_linked_assets(self):
        collector, assets = self._collect()
        assert collector.collection_mode == "sdk"
        edges, _ = _link(assets)
        g = _Graph(assets, edges)
        assert g.a(SNET_AKS).metadata["address_prefix"] == "10.1.0.0/24"
        assert g.has(VNET, SNET_AKS, EdgeType.CONTAINS)
        assert g.has(SNET_AKS, NSG, EdgeType.ATTACHED_TO)
        kv = g.a(KV)
        assert kv.metadata["vault_uri"] == "https://kv-app.vault.azure.net/"
        assert kv.metadata["rbac_authorization"] is True
        assert "discovered_via" not in kv.metadata  # detailed copy beat the sweep hit
        assert not kv.is_internet_exposed
        server = g.a(f"{RG}/providers/Microsoft.Sql/servers/sql-app")
        db = g.a(f"{RG}/providers/Microsoft.Sql/servers/sql-app/databases/appdb")
        assert server.metadata["role"] == "server" and server.metadata["allow_azure_services"]
        assert server.is_internet_exposed and server.metadata["firewall_rules"][0]["name"] == "office"
        assert db.metadata["role"] == "database" and db.metadata["edition"] == "Standard"
        assert f"{RG}/providers/Microsoft.Sql/servers/sql-app/databases/master".lower() not in g.by_arn
        assert g.has(server.arn, db.arn, EdgeType.CONTAINS)
        # sweep hit keeps kind and identity
        web = g.a(WEB)
        assert web.asset_type == AssetType.CLOUD_FUNCTION
        assert web.metadata["discovered_via"] == "arm-sweep"
        assert f"entra:principal/{VM_PRINCIPAL}" in web.metadata["aliases"]
        assert g.has(RG, VNET, EdgeType.CONTAINS)
        assert g.a(f"/subscriptions/{SUB}").asset_type == AssetType.CLOUD_ACCOUNT
        sg = _run(collector.collect_edges())
        assert any(e.source_id == "203.0.113.0/24" and e.port_range == "443" for e in sg)

    def test_one_service_failure_keeps_other_assets(self):
        collector, assets = self._collect(fail_storage=True)
        assert "storage" in collector.service_errors
        arns = {a.arn.lower() for a in assets}
        assert VNET.lower() in arns and KV.lower() in arns

    def test_graph_failure_falls_back(self):
        clients = _fake_sdk_clients()

        class Broken:
            def resources(self, request):
                raise RuntimeError("AuthorizationFailed")

        collector = AzureDeepInventoryCollector(object(), SUB, graph_client_factory=lambda c: Broken())
        collector._client = lambda kind: clients[kind]
        assets = _run(collector.collect())
        assert collector.collection_mode == "sdk"
        assert "resource_graph" in collector.service_errors
        assert any(a.arn == VNET for a in assets)


# ── multi-subscription orchestration ──


class TestMultiSubscription:
    def _collector(self, override, subscription_ids=None, monkeypatch=None):
        from cloudg.collectors.multi import MultiAccountCollector
        from cloudg.config import CloudGConfig

        cfg = CloudGConfig(providers=["azure"])
        cfg.azure.regions = ["eastus"]
        cfg.azure.subscription_ids = subscription_ids or []
        return MultiAccountCollector(cfg, collector_overrides={"azure": override})

    def test_edge_failure_keeps_assets(self):
        class EdgeFails:
            def __init__(self, credential, subscription_id):
                self.service_errors = {"sql": "boom"}
                self.sub = subscription_id

            async def collect(self):
                return [CloudAsset(arn=VNET, name="v", asset_type=AssetType.VNET, provider=CloudProvider.AZURE,
                                   account_id=self.sub)]

            async def collect_edges(self):
                raise ValueError("source_id None")

        multi = self._collector(EdgeFails)
        assets, edges = _run(multi._collect_azure_single(SUB, credential=object()))
        assert len(assets) == 1 and edges == []
        services = {s.service: s.status.value for s in multi._coverage[0].services}
        assert services["azure_edges"] == "FAILED"
        assert services["azure_sql"] == "FAILED"
        assert services["azure_full"] == "PARTIAL"

    def test_all_enabled_subscriptions_enumerated(self, monkeypatch):
        import cloudg.collectors.azure as azure_mod
        import cloudg.credentials as creds

        seen = []

        class Recorder:
            def __init__(self, credential, subscription_id):
                seen.append(subscription_id)
                self.service_errors = {}

            async def collect(self):
                return []

            async def collect_edges(self):
                return []

        monkeypatch.setattr(creds, "build_azure_credential", lambda cfg: object())
        monkeypatch.setattr(
            azure_mod, "list_subscriptions",
            lambda cred, include_disabled=False: [{"subscription_id": "s-a"}, {"subscription_id": "s-b"}],
        )
        multi = self._collector(Recorder)
        _run(multi._collect_azure_multi())
        assert sorted(seen) == ["s-a", "s-b"]

        seen.clear()
        multi = self._collector(Recorder, subscription_ids=["explicit"])
        _run(multi._collect_azure_multi())
        assert seen == ["explicit"]


def test_list_subscriptions_filters_enabled(monkeypatch):
    import cloudg.collectors.azure as azure_mod

    subs = [
        SimpleNamespace(subscription_id="s1", display_name="a", state="Enabled", tenant_id="t"),
        SimpleNamespace(subscription_id="s2", display_name="b", state="Disabled", tenant_id="t"),
    ]
    monkeypatch.setattr(
        azure_mod, "subscription_client",
        lambda cred: SimpleNamespace(subscriptions=SimpleNamespace(list=lambda: subs)),
    )
    assert [s["subscription_id"] for s in azure_mod.list_subscriptions(object())] == ["s1"]
    assert len(azure_mod.list_subscriptions(object(), include_disabled=True)) == 2


# ── tenant hierarchy ──


TENANT = "99999999-9999-9999-9999-999999999999"


def _mg(name, parent, display=None):
    return {
        "id": f"/providers/Microsoft.Management/managementGroups/{name}",
        "name": name,
        "type": "microsoft.management/managementgroups",
        "tenantId": TENANT,
        "properties": {
            "displayName": display or name,
            "details": {"parent": {"id": f"/providers/Microsoft.Management/managementGroups/{parent}",
                                   "name": parent} if parent else None},
        },
    }


def _hierarchy_tables():
    return {
        "resourcecontainers": [
            _mg(TENANT, None, "Tenant Root Group"),
            _mg("contoso", TENANT, "Contoso"),
            _mg("contoso-platform", "contoso", "Platform"),
            _mg("contoso-landingzones", "contoso", "Landing Zones"),
            _mg("contoso-corp", "contoso-landingzones", "Corp"),
            {
                "id": f"/subscriptions/{SUB}",
                "name": "Production",
                "type": "microsoft.resources/subscriptions",
                "tenantId": TENANT,
                "subscriptionId": SUB,
                "properties": {
                    "state": "Enabled",
                    "managementGroupAncestorsChain": [
                        {"name": "contoso-corp"}, {"name": "contoso-landingzones"}, {"name": "contoso"},
                        {"name": TENANT},
                    ],
                },
            },
        ],
        "policyresources": [
            {
                "id": "/providers/Microsoft.Management/managementGroups/contoso/providers/"
                "Microsoft.Authorization/policyAssignments/deny-public-ip",
                "name": "deny-public-ip",
                "type": "microsoft.authorization/policyassignments",
                "identity": {"type": "SystemAssigned", "principalId": "12121212-0000-0000-0000-000000000000"},
                "properties": {
                    "displayName": "Deny public IPs",
                    "scope": "/providers/microsoft.management/managementgroups/CONTOSO",
                    "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/x",
                    "enforcementMode": "Default",
                    "notScopes": [f"/subscriptions/{SUB}/resourceGroups/rg-hub"],
                },
            },
            {
                "id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyAssignments/audit-tags",
                "name": "audit-tags",
                "type": "microsoft.authorization/policyassignments",
                "subscriptionId": SUB,
                "properties": {
                    "displayName": "Audit tags",
                    "scope": f"/subscriptions/{SUB}",
                    "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/y",
                    "enforcementMode": "DoNotEnforce",
                },
            },
            {
                "id": f"{RG}/providers/Microsoft.Authorization/policyExemptions/exempt-app",
                "name": "exempt-app",
                "type": "microsoft.authorization/policyexemptions",
                "subscriptionId": SUB,
                "properties": {
                    "policyAssignmentId": "/providers/Microsoft.Management/managementGroups/contoso/providers/"
                    "Microsoft.Authorization/policyAssignments/deny-public-ip",
                    "exemptionCategory": "Waiver",
                },
            },
        ],
    }


class TestHierarchy:
    def test_alz_archetype(self):
        assert alz_archetype("contoso-corp") == "corp"
        assert alz_archetype("mg-1", "Landing Zones") == "landingzones"
        assert alz_archetype("finance") is None

    def test_discover_and_link(self):
        fake = FakeGraph(_hierarchy_tables())
        assets = discover_azure_hierarchy(object(), graph_client_factory=lambda c: fake)
        policy_requests = [r for r in fake.requests if r.query.startswith("policyresources")]
        assert policy_requests and policy_requests[0].management_groups == [TENANT]

        # add a resource group from the subscription collector so scopes resolve
        rg = CloudAsset(arn=f"/subscriptions/{SUB}/resourceGroups/rg-hub", name="rg-hub",
                        asset_type=AssetType.RESOURCE_GROUP, provider=CloudProvider.AZURE, account_id=SUB)
        rg_app = CloudAsset(arn=RG, name="rg-app", asset_type=AssetType.RESOURCE_GROUP,
                            provider=CloudProvider.AZURE, account_id=SUB)
        edges, linker = _link(assets + [rg, rg_app])
        g = _Graph(assets + [rg, rg_app], edges)
        mg = "/providers/Microsoft.Management/managementGroups/"
        root = g.a(mg + TENANT)
        assert root.metadata["is_tenant_root"] and root.asset_type == AssetType.ORG_UNIT
        assert g.has(mg + TENANT, mg + "contoso", EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT")
        assert g.has(mg + "contoso-landingzones", mg + "contoso-corp", EdgeType.CONTAINS)
        corp = g.a(mg + "contoso-corp")
        assert corp.metadata["landing_zone"] and corp.metadata["alz_archetype"] == "corp"
        assert not g.a(mg + "contoso").metadata["landing_zone"]
        sub = g.a(f"/subscriptions/{SUB}")
        assert sub.asset_type == AssetType.CLOUD_ACCOUNT and sub.metadata["state"] == "Enabled"
        assert sub.metadata["management_group_path"][-1] == "contoso-corp"
        assert g.has(mg + "contoso-corp", f"/subscriptions/{SUB}", EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT")
        deny = next(a for a in assets if a.name == "Deny public IPs")
        assert deny.asset_type == AssetType.GUARDRAIL and deny.metadata["enforced"]
        assert g.has(deny.arn, mg + "contoso", EdgeType.GOVERNS, "COMPLIANCE_GOVERNS")
        audit = next(a for a in assets if a.name == "Audit tags")
        assert audit.metadata["enforced"] is False and audit.metadata["initiative"]
        assert g.has(audit.arn, f"/subscriptions/{SUB}", EdgeType.GOVERNS)
        exemption = next(a for a in assets if a.metadata.get("exemption"))
        assert g.has(exemption.arn, RG, EdgeType.GOVERNS)
        assert g.has(exemption.arn, deny.arn, EdgeType.REFERENCES)
        assert not linker.unresolved

    def test_hierarchy_subscription_wins_dedupe(self):
        from cloudg.inventory.mapper import deduplicate

        fake = FakeGraph(_hierarchy_tables())
        hierarchy = discover_azure_hierarchy(object(), graph_client_factory=lambda c: fake, include_policies=False)
        builder = AzureAssetBuilder(SUB)
        builder.include_subscription()
        collected = builder.build()
        merged, _ = deduplicate(hierarchy + collected, [])
        subs = [a for a in merged if a.arn == f"/subscriptions/{SUB}"]
        assert len(subs) == 1 and subs[0].metadata.get("parent_management_group") == "contoso-corp"
