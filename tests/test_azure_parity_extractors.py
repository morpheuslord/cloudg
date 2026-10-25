"""Azure parity: Resource Graph row extractors (hybrid, edge, governance, data, ops)."""

from __future__ import annotations

import pytest

from cloudg.inventory.azure_graph import AzureAssetBuilder
from cloudg.inventory.linker import RelationshipLinker
from cloudg.schema.models import AssetType, EdgeType
from tests.test_azure_inventory import SUB, _Graph, _row

SUB_REF = f"/subscriptions/{SUB}"
RG = f"{SUB_REF}/resourceGroups/rg-x"
P = f"{RG}/providers"
NET = f"{P}/Microsoft.Network"

VNET = f"{NET}/virtualNetworks/vnet"
SNET = f"{VNET}/subnets/default"
NIC = f"{NET}/networkInterfaces/nva-nic"
WAN = f"{NET}/virtualWans/wan"
HUB = f"{NET}/virtualHubs/hub"
RS = f"{NET}/virtualHubs/routeserver"
FW = f"{NET}/azureFirewalls/fw"
ERC = f"{NET}/expressRouteCircuits/erc-dc1"
ERC2 = f"{NET}/expressRouteCircuits/erc-dc2"
ERGW = f"{NET}/expressRouteGateways/ergw"
VPNGW = f"{NET}/vpnGateways/vpngw"
SITE = f"{NET}/vpnSites/branch"
LGW = f"{NET}/localNetworkGateways/onprem"
VGW = f"{NET}/virtualNetworkGateways/vgw"
IPG = f"{NET}/ipGroups/partners"
PREFIX = f"{NET}/publicIPPrefixes/egress"
PIP = f"{NET}/publicIPAddresses/pip-a"
TM = f"{NET}/trafficManagerProfiles/tm"
WEB = f"{P}/Microsoft.Web/sites/web"
APPGW = f"{NET}/applicationGateways/agw"
LISTENER = f"{APPGW}/httpListeners/https"
POOL = f"{APPGW}/backendAddressPools/pool"
WAF = f"{NET}/ApplicationGatewayWebApplicationFirewallPolicies/waf"
FDWAF = f"{NET}/frontdoorWebApplicationFirewallPolicies/fdwaf"
FD = f"{NET}/frontDoors/classic"
PLS = f"{NET}/privateLinkServices/pls"
AFD = f"{P}/Microsoft.Cdn/profiles/afd"
KV = f"{P}/Microsoft.KeyVault/vaults/kv"
TS = f"{P}/Microsoft.Resources/templateSpecs/vm"
TSV = f"{TS}/versions/1.0"
APP = f"{P}/Microsoft.Solutions/applications/vendor-app"
APPDEF = f"{P}/Microsoft.Solutions/applicationDefinitions/vendor-def"
GAL = f"{P}/Microsoft.Compute/galleries/images"
IMGV = f"{GAL}/images/ubuntu/versions/1.0.0"
VM = f"{P}/Microsoft.Compute/virtualMachines/vm"
AVSET = f"{P}/Microsoft.Compute/availabilitySets/avset"
PPG = f"{P}/Microsoft.Compute/proximityPlacementGroups/ppg"
SYN = f"{P}/Microsoft.Synapse/workspaces/syn"
HDI = f"{P}/Microsoft.HDInsight/clusters/hdi"
ST = f"{P}/Microsoft.Storage/storageAccounts/stx"
MI = f"{P}/Microsoft.Sql/managedInstances/sqlmi"
MI2 = f"{P}/Microsoft.Sql/managedInstances/sqlmi-dr"
NETAPP_VOL = f"{P}/Microsoft.NetApp/netAppAccounts/anf/capacityPools/p1/volumes/data"
NETAPP_DST = f"{P}/Microsoft.NetApp/netAppAccounts/anf2/capacityPools/p1/volumes/data"
SNAP_POLICY = f"{P}/Microsoft.NetApp/netAppAccounts/anf/snapshotPolicies/hourly"
BVAULT = f"{P}/Microsoft.NetApp/netAppAccounts/anf/backupVaults/bv"
PURVIEW = f"{P}/Microsoft.Purview/accounts/pv"
HUBWS = f"{P}/Microsoft.MachineLearningServices/workspaces/ai-hub"
PROJ = f"{P}/Microsoft.MachineLearningServices/workspaces/ai-proj"
COMPUTE = f"{HUBWS}/computes/gpu"
CONNX = f"{HUBWS}/connections/oai"
LAW = f"{P}/Microsoft.OperationalInsights/workspaces/law"
AG = f"{P}/Microsoft.Insights/actionGroups/oncall"
FUNC = f"{P}/Microsoft.Web/sites/func"
MALERT = f"{P}/Microsoft.Insights/metricAlerts/cpu"
LALERT = f"{P}/Microsoft.Insights/scheduledQueryRules/errors"
AALERT = f"{P}/Microsoft.Insights/activityLogAlerts/deletes"
SMART = f"{P}/microsoft.alertsmanagement/smartDetectorAlertRules/failures"
ARC = f"{P}/Microsoft.HybridCompute/machines/onprem-1"
ARC_EXT = f"{ARC}/extensions/AzureMonitorLinuxAgent"
SOLUTION = f"{P}/Microsoft.OperationsManagement/solutions/SecurityInsights(law)"
SECAUTO = f"{P}/Microsoft.Security/automations/export"
EH = f"{P}/Microsoft.EventHub/namespaces/ehx"
EXT_SUB = f"{ST}/providers/Microsoft.EventGrid/eventSubscriptions/on-upload"
B2C = f"{P}/Microsoft.AzureActiveDirectory/b2cDirectories/contosob2c.onmicrosoft.com"
DEVP = f"{P}/Microsoft.DevCenter/projects/p"
ENVT = f"{DEVP}/environmentTypes/prod"
AUTHS = f"{P}/Microsoft.ApiManagement/service/apim/authorizationServers/oauth"
DEP = f"{RG}/providers/Microsoft.Resources/deployments/from-spec"
USER_OID = "eeee0000-0000-0000-0000-000000000001"
DISK = f"{P}/Microsoft.Compute/disks/data-1"
SNAP = f"{P}/Microsoft.Compute/snapshots/data-1-snap"


def _rows() -> list[dict]:
    return [
        _row(
            VNET,
            "microsoft.network/virtualnetworks",
            {"subnets": [{"id": SNET, "name": "default", "properties": {}}]},
        ),
        _row(
            NIC,
            "microsoft.network/networkinterfaces",
            {
                "enableIPForwarding": True,
                "ipConfigurations": [
                    {
                        "id": f"{NIC}/ipConfigurations/ip",
                        "properties": {"privateIPAddress": "10.0.0.4", "subnet": {"id": SNET}},
                    }
                ],
            },
        ),
        _row(
            WAN, "microsoft.network/virtualwans", {"type": "Standard", "virtualHubs": [{"id": HUB}]}
        ),
        _row(
            HUB,
            "microsoft.network/virtualhubs",
            {
                "virtualWan": {"id": WAN},
                "azureFirewall": {"id": FW},
                "expressRouteGateway": {"id": ERGW},
                "vpnGateway": {"id": VPNGW},
                "addressPrefix": "10.100.0.0/23",
            },
        ),
        _row(RS, "microsoft.network/virtualhubs", {"virtualRouterIps": ["10.0.1.4", "10.0.1.5"]}),
        _row(
            f"{RS}/bgpConnections/nva",
            "microsoft.network/virtualhubs/bgpconnections",
            {"peerIp": "10.0.0.4", "peerAsn": 65010},
        ),
        _row(
            f"{RS}/ipConfigurations/ipconfig",
            "microsoft.network/virtualhubs/ipconfigurations",
            {"subnet": {"id": SNET}, "privateIPAddress": "10.0.1.4"},
        ),
        _row(FW, "microsoft.network/azurefirewalls", {"virtualHub": {"id": HUB}}),
        _row(
            ERC,
            "microsoft.network/expressroutecircuits",
            {
                "serviceProviderProperties": {
                    "serviceProviderName": "Equinix",
                    "peeringLocation": "Amsterdam",
                    "bandwidthInMbps": 1000,
                },
                "peerings": [
                    {
                        "name": "AzurePrivatePeering",
                        "properties": {
                            "peeringType": "AzurePrivatePeering",
                            "peerASN": 65001,
                            "vlanId": 100,
                            "connections": [
                                {
                                    "properties": {
                                        "peerExpressRouteCircuitPeering": {
                                            "id": f"{ERC2}/peerings/AzurePrivatePeering"
                                        }
                                    }
                                }
                            ],
                        },
                    }
                ],
                "globalReachEnabled": True,
            },
        ),
        _row(ERC2, "microsoft.network/expressroutecircuits", {}),
        _row(
            ERGW,
            "microsoft.network/expressroutegateways",
            {
                "virtualHub": {"id": HUB},
                "expressRouteConnections": [
                    {
                        "properties": {
                            "expressRouteCircuitPeering": {
                                "id": f"{ERC}/peerings/AzurePrivatePeering"
                            }
                        }
                    }
                ],
            },
        ),
        _row(
            VPNGW,
            "microsoft.network/vpngateways",
            {
                "virtualHub": {"id": HUB},
                "connections": [{"properties": {"remoteVpnSite": {"id": SITE}}}],
            },
        ),
        _row(
            SITE,
            "microsoft.network/vpnsites",
            {
                "ipAddress": "198.51.100.10",
                "virtualWan": {"id": WAN},
                "addressSpace": {"addressPrefixes": ["192.168.0.0/16"]},
            },
        ),
        _row(
            LGW,
            "microsoft.network/localnetworkgateways",
            {
                "gatewayIpAddress": "203.0.113.5",
                "localNetworkAddressSpace": {"addressPrefixes": ["172.16.0.0/12"]},
                "bgpSettings": {"asn": 65020},
            },
        ),
        _row(
            f"{NET}/connections/s2s",
            "microsoft.network/connections",
            {
                "virtualNetworkGateway1": {"id": VGW},
                "localNetworkGateway2": {"id": LGW},
                "connectionType": "IPsec",
            },
        ),
        _row(
            VGW,
            "microsoft.network/virtualnetworkgateways",
            {
                "gatewayType": "Vpn",
                "vpnType": "RouteBased",
                "enableBgp": True,
                "vpnClientConfiguration": {
                    "vpnClientProtocols": ["OpenVPN"],
                    "aadTenant": "https://login.microsoftonline.com/t",
                },
            },
        ),
        _row(
            IPG,
            "microsoft.network/ipgroups",
            {"ipAddresses": ["198.51.100.0/24"], "firewalls": [{"id": FW}]},
        ),
        _row(PIP, "microsoft.network/publicipaddresses", {"ipAddress": "20.0.0.1"}),
        _row(
            PREFIX,
            "microsoft.network/publicipprefixes",
            {"ipPrefix": "20.0.0.0/30", "publicIPAddresses": [{"id": PIP}]},
        ),
        _row(WEB, "microsoft.web/sites", {"defaultHostName": "web.azurewebsites.net"}, kind="app"),
        _row(
            TM,
            "microsoft.network/trafficmanagerprofiles",
            {
                "dnsConfig": {"fqdn": "shop.trafficmanager.net"},
                "trafficRoutingMethod": "Priority",
                "endpoints": [
                    {
                        "name": "primary",
                        "type": "Microsoft.Network/trafficManagerProfiles/azureEndpoints",
                        "properties": {"targetResourceId": WEB},
                    },
                    {
                        "name": "dr",
                        "type": "Microsoft.Network/trafficManagerProfiles/externalEndpoints",
                        "properties": {"target": "dr.example.net"},
                    },
                ],
            },
        ),
        _row(
            APPGW,
            "microsoft.network/applicationgateways",
            {
                "frontendIPConfigurations": [
                    {
                        "id": f"{APPGW}/frontendIPConfigurations/public",
                        "properties": {"publicIPAddress": {"id": PIP}},
                    }
                ],
                "frontendPorts": [
                    {"id": f"{APPGW}/frontendPorts/p443", "properties": {"port": 443}}
                ],
                "sslCertificates": [
                    {
                        "id": f"{APPGW}/sslCertificates/c",
                        "properties": {"keyVaultSecretId": "https://kv.vault.azure.net/secrets/c"},
                    }
                ],
                "backendAddressPools": [
                    {
                        "id": POOL,
                        "name": "pool",
                        "properties": {"backendAddresses": [{"fqdn": "web.azurewebsites.net"}]},
                    }
                ],
                "httpListeners": [
                    {
                        "id": LISTENER,
                        "name": "https",
                        "properties": {
                            "frontendIPConfiguration": {
                                "id": f"{APPGW}/frontendIPConfigurations/public"
                            },
                            "frontendPort": {"id": f"{APPGW}/frontendPorts/p443"},
                            "protocol": "Https",
                            "hostNames": ["shop.contoso.com"],
                            "sslCertificate": {"id": f"{APPGW}/sslCertificates/c"},
                            "firewallPolicy": {"id": WAF},
                        },
                    }
                ],
                "requestRoutingRules": [
                    {
                        "name": "r",
                        "properties": {
                            "httpListener": {"id": LISTENER},
                            "backendAddressPool": {"id": POOL},
                        },
                    }
                ],
            },
        ),
        _row(
            WAF,
            "microsoft.network/applicationgatewaywebapplicationfirewallpolicies",
            {
                "policySettings": {"state": "Enabled", "mode": "Detection"},
                "managedRules": {
                    "managedRuleSets": [{"ruleSetType": "OWASP", "ruleSetVersion": "3.2"}]
                },
                "applicationGateways": [{"id": APPGW}],
                "httpListeners": [{"id": LISTENER}],
            },
        ),
        _row(FD, "microsoft.network/frontdoors", {"frontendEndpoints": []}),
        _row(
            FDWAF,
            "microsoft.network/frontdoorwebapplicationfirewallpolicies",
            {
                "policySettings": {"enabledState": "Enabled", "mode": "Prevention"},
                "frontendEndpointLinks": [{"id": f"{FD}/frontendEndpoints/default"}],
            },
        ),
        _row(
            PLS,
            "microsoft.network/privatelinkservices",
            {
                "visibility": {"subscriptions": ["99999999-9999-9999-9999-999999999999"]},
                "autoApproval": {"subscriptions": ["99999999-9999-9999-9999-999999999999"]},
                "fqdns": ["svc.contoso.com"],
            },
        ),
        _row(
            f"{AFD}/ruleSets/rs/rules/override",
            "microsoft.cdn/profiles/rulesets/rules",
            {
                "order": 1,
                "actions": [
                    {
                        "name": "RouteConfigurationOverride",
                        "parameters": {
                            "originGroupOverride": {
                                "originGroup": {"id": f"{AFD}/originGroups/api"}
                            }
                        },
                    }
                ],
            },
        ),
        _row(f"{AFD}/originGroups/api", "microsoft.cdn/profiles/origingroups", {}),
        _row(
            f"{AFD}/customDomains/shop",
            "microsoft.cdn/profiles/customdomains",
            {
                "hostName": "shop.contoso.com",
                "tlsSettings": {
                    "certificateType": "CustomerCertificate",
                    "secret": {"id": f"{AFD}/secrets/cert"},
                },
            },
        ),
        _row(f"{AFD}/secrets/cert", "microsoft.cdn/profiles/secrets", {}),
        _row(KV, "microsoft.keyvault/vaults", {"vaultUri": "https://kv.vault.azure.net/"}),
        # governance
        _row(TS, "microsoft.resources/templatespecs", {"description": "VM baseline"}),
        _row(TSV, "microsoft.resources/templatespecs/versions", {}),
        _row(
            DEP,
            "microsoft.resources/deployments",
            {"templateLink": {"id": TSV}, "outputResources": [{"id": VM}]},
        ),
        _row(
            APP,
            "microsoft.solutions/applications",
            {
                "managedResourceGroupId": f"{SUB_REF}/resourceGroups/mrg-vendor",
                "applicationDefinitionId": APPDEF,
                "publisherTenantId": "vendor-tenant",
                "authorizations": [{"principalId": "vendor-ops", "roleDefinitionId": "owner"}],
            },
        ),
        _row(
            APPDEF,
            "microsoft.solutions/applicationdefinitions",
            {
                "lockLevel": "ReadOnly",
                "authorizations": [{"principalId": "vendor-def", "roleDefinitionId": "c"}],
            },
        ),
        _row(
            GAL,
            "microsoft.compute/galleries",
            {
                "sharingProfile": {
                    "permissions": "Groups",
                    "groups": [
                        {"type": "Subscriptions", "ids": ["88888888-8888-8888-8888-888888888888"]},
                    ],
                }
            },
        ),
        _row(
            IMGV,
            "microsoft.compute/galleries/images/versions",
            {
                "storageProfile": {"source": {"id": VM}},
                "publishingProfile": {
                    "targetRegions": [{"name": "West Europe"}, {"name": "East US"}]
                },
            },
        ),
        _row(VM, "microsoft.compute/virtualmachines", {"availabilitySet": {"id": AVSET}}),
        _row(
            AVSET,
            "microsoft.compute/availabilitysets",
            {
                "virtualMachines": [{"id": VM}],
                "platformFaultDomainCount": 2,
                "proximityPlacementGroup": {"id": PPG},
            },
        ),
        _row(PPG, "microsoft.compute/proximityplacementgroups", {}),
        _row(DISK, "microsoft.compute/disks", {"networkAccessPolicy": "AllowAll"}),
        _row(
            SNAP,
            "microsoft.compute/snapshots",
            {
                "creationData": {"sourceResourceId": DISK},
                "incremental": True,
                "networkAccessPolicy": "DenyAll",
            },
        ),
        _row(B2C, "microsoft.azureactivedirectory/b2cdirectories", {"tenantId": "b2c-tenant"}),
        # data
        _row(
            ST,
            "microsoft.storage/storageaccounts",
            {"primaryEndpoints": {"dfs": "https://stx.dfs.core.windows.net/"}},
        ),
        _row(
            SYN,
            "microsoft.synapse/workspaces",
            {
                "defaultDataLakeStorage": {"accountUrl": "https://stx.dfs.core.windows.net"},
                "connectivityEndpoints": {"sql": "syn.sql.azuresynapse.net"},
                "virtualNetworkProfile": {"computeSubnetId": SNET},
            },
        ),
        _row(f"{SYN}/sqlPools/dw", "microsoft.synapse/workspaces/sqlpools", {"status": "Online"}),
        _row(
            HDI,
            "microsoft.hdinsight/clusters",
            {
                "clusterDefinition": {"kind": "spark"},
                "computeProfile": {
                    "roles": [{"name": "workernode", "virtualNetworkProfile": {"subnet": SNET}}]
                },
                "storageProfile": {
                    "storageaccounts": [
                        {
                            "name": "stx.dfs.core.windows.net",
                            "resourceId": ST,
                            "msiResourceId": f"{P}/Microsoft.ManagedIdentity/userAssignedIdentities/hdi",
                        }
                    ]
                },
                "connectivityEndpoints": [{"name": "HTTPS", "location": "hdi.azurehdinsight.net"}],
            },
        ),
        _row(
            MI,
            "microsoft.sql/managedinstances",
            {
                "subnetId": SNET,
                "fullyQualifiedDomainName": "sqlmi.abc.database.windows.net",
                "publicDataEndpointEnabled": True,
                "administrators": {"sid": USER_OID, "principalType": "User"},
            },
        ),
        _row(MI2, "microsoft.sql/managedinstances", {}),
        _row(
            f"{RG}/providers/Microsoft.Sql/locations/westeurope/instanceFailoverGroups/fog",
            "microsoft.sql/locations/instancefailovergroups",
            {
                "managedInstancePairs": [
                    {"primaryManagedInstanceId": MI, "partnerManagedInstanceId": MI2}
                ],
            },
        ),
        _row(
            f"{P}/Microsoft.Sql/servers/sql/elasticPools/pool",
            "microsoft.sql/servers/elasticpools",
            {"zoneRedundant": True},
        ),
        _row(
            NETAPP_VOL,
            "microsoft.netapp/netappaccounts/capacitypools/volumes",
            {
                "subnetId": SNET,
                "mountTargets": [{"ipAddress": "10.0.0.20"}],
                "protocolTypes": ["NFSv4.1"],
                "exportPolicy": {"rules": [{"allowedClients": "0.0.0.0/0"}]},
                "dataProtection": {
                    "replication": {"endpointType": "src", "remoteVolumeResourceId": NETAPP_DST},
                    "backup": {"backupVaultId": BVAULT},
                    "snapshot": {"snapshotPolicyId": SNAP_POLICY},
                },
            },
        ),
        _row(NETAPP_DST, "microsoft.netapp/netappaccounts/capacitypools/volumes", {}),
        _row(SNAP_POLICY, "microsoft.netapp/netappaccounts/snapshotpolicies", {}),
        _row(BVAULT, "microsoft.netapp/netappaccounts/backupvaults", {}),
        _row(
            PURVIEW,
            "microsoft.purview/accounts",
            {
                "managedResources": {"storageAccount": ST},
                "publicNetworkAccess": "Disabled",
            },
        ),
        _row(HUBWS, "microsoft.machinelearningservices/workspaces", {}, kind="Hub"),
        _row(
            PROJ,
            "microsoft.machinelearningservices/workspaces",
            {"hubResourceId": HUBWS},
            kind="Project",
        ),
        _row(
            COMPUTE,
            "microsoft.machinelearningservices/workspaces/computes",
            {
                "computeType": "AmlCompute",
                "properties": {
                    "vmSize": "Standard_NC6",
                    "enableNodePublicIp": True,
                    "subnet": {"id": SNET},
                },
            },
        ),
        _row(
            CONNX,
            "microsoft.machinelearningservices/workspaces/connections",
            {
                "category": "AzureOpenAI",
                "target": "https://oai.openai.azure.com/",
                "authType": "ApiKey",
                "credentials": {"key": "secret"},
            },
        ),
        # operations
        _row(LAW, "microsoft.operationalinsights/workspaces", {"customerId": "CUST-9"}),
        _row(FUNC, "microsoft.web/sites", {}, kind="functionapp"),
        _row(
            AG,
            "microsoft.insights/actiongroups",
            {
                "enabled": True,
                "emailReceivers": [{"name": "ops", "emailAddress": "ops@contoso.com"}],
                "smsReceivers": [{"name": "pager", "phoneNumber": "5551234"}],
                "webhookReceivers": [
                    {"name": "pd", "serviceUri": "https://events.pagerduty.com/integration/x"}
                ],
                "azureFunctionReceivers": [{"name": "fn", "functionAppResourceId": FUNC}],
                "eventHubReceivers": [
                    {"name": "eh", "eventHubNameSpace": "ehx", "eventHubName": "alerts"}
                ],
            },
        ),
        _row(f"{EH}/eventhubs/alerts", "microsoft.eventhub/namespaces/eventhubs", {}),
        _row(
            MALERT,
            "microsoft.insights/metricalerts",
            {
                "scopes": [VM],
                "severity": 2,
                "enabled": True,
                "criteria": {"allOf": [{"metricName": "Percentage CPU"}]},
                "actions": [{"actionGroupId": AG}],
            },
        ),
        _row(
            LALERT,
            "microsoft.insights/scheduledqueryrules",
            {"scopes": [LAW], "actions": {"actionGroups": [AG]}},
        ),
        _row(
            AALERT,
            "microsoft.insights/activitylogalerts",
            {
                "scopes": [SUB_REF],
                "condition": {
                    "allOf": [
                        {
                            "field": "operationName",
                            "equals": "Microsoft.Compute/virtualMachines/delete",
                        }
                    ]
                },
                "actions": {"actionGroups": [{"actionGroupId": AG}]},
            },
        ),
        _row(
            SMART,
            "microsoft.alertsmanagement/smartdetectoralertrules",
            {"scope": [FUNC], "actionGroups": {"groupIds": [AG]}},
        ),
        _row(ARC, "microsoft.hybridcompute/machines", {"osName": "linux", "status": "Connected"}),
        _row(
            ARC_EXT,
            "microsoft.hybridcompute/machines/extensions",
            {"publisher": "Microsoft.Azure.Monitor", "settings": {"workspaceId": "CUST-9"}},
        ),
        _row(SOLUTION, "microsoft.operationsmanagement/solutions", {"workspaceResourceId": LAW}),
        _row(
            SECAUTO,
            "microsoft.security/automations",
            {
                "actions": [
                    {"actionType": "EventHub", "eventHubResourceId": f"{EH}/eventhubs/alerts"},
                    {
                        "actionType": "LogicApp",
                        "logicAppResourceId": f"{P}/Microsoft.Logic/workflows/notify",
                    },
                ]
            },
        ),
        _row(f"{P}/Microsoft.Logic/workflows/notify", "microsoft.logic/workflows", {}),
        _row(
            EXT_SUB,
            "microsoft.eventgrid/eventsubscriptions",
            {
                "destination": {
                    "endpointType": "AzureFunction",
                    "properties": {"resourceId": FUNC},
                },
                "filter": {"includedEventTypes": ["Microsoft.Storage.BlobCreated"]},
            },
        ),
        _row(DEVP, "microsoft.devcenter/projects", {}),
        _row(
            ENVT,
            "microsoft.devcenter/projects/environmenttypes",
            {
                "deploymentTargetId": SUB_REF,
                "userRoleAssignments": {USER_OID: {"roles": {"r": {}}}},
            },
        ),
        _row(
            AUTHS,
            "microsoft.apimanagement/service/authorizationservers",
            {
                "authorizationEndpoint": "https://login.contoso.com/authorize",
                "clientSecret": "s3cret",
            },
        ),
    ]


@pytest.fixture(scope="module")
def g():
    builder = AzureAssetBuilder(SUB)
    builder.add_rows(_rows())
    builder.include_subscription()
    assets = builder.build()
    linker = RelationshipLinker(assets)
    edges = linker.link()
    return _Graph(assets + linker.external_assets, edges)


class TestHybrid:
    def test_virtual_wan_and_route_server(self, g):
        assert g.has(WAN, HUB, EdgeType.CONTAINS)
        assert g.has(HUB, FW, EdgeType.CONTAINS)
        assert g.has(HUB, ERGW, EdgeType.CONTAINS)
        assert g.a(RS).metadata["route_server"] is True
        assert g.has(f"{RS}/bgpConnections/nva", NIC, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.has(
            SNET, f"{RS}/ipConfigurations/ipconfig", EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE"
        )

    def test_expressroute_and_vpn(self, g):
        assert g.has(ERC, ERC2, EdgeType.ROUTE, "TRANSIT_ROUTED")  # Global Reach
        assert g.a(ERC).metadata["provider"] == "Equinix"
        assert g.has(ERGW, ERC, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.has(VPNGW, SITE, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.a(SITE).asset_type == AssetType.CUSTOMER_GATEWAY
        assert g.has(WAN, SITE, EdgeType.CONTAINS)
        lgw = g.a(LGW)
        assert (
            lgw.metadata["address_space"] == ["172.16.0.0/12"] and lgw.metadata["bgp_asn"] == 65020
        )
        assert g.has(f"{NET}/connections/s2s", LGW, EdgeType.ATTACHED_TO, "TRANSIT_ROUTED")
        assert g.a(VGW).metadata["point_to_site"] is True

    def test_ip_groups_and_prefixes(self, g):
        assert g.has(FW, IPG, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.has(PREFIX, PIP, EdgeType.CONTAINS)
        assert g.a(PREFIX).is_internet_exposed

    def test_traffic_manager(self, g):
        assert g.has(TM, WEB, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert g.a(TM).metadata["routing_method"] == "Priority"
        assert g.a(TM).is_internet_exposed

    def test_appgw_listener_and_waf(self, g):
        listener = g.a(LISTENER)
        assert listener.asset_type == AssetType.LB_LISTENER
        assert listener.metadata["port"] == 443 and listener.is_internet_exposed
        assert g.has(listener.arn, WEB, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert g.has(WAF, listener.arn, EdgeType.PROTECTS, "PROTECTED_BY_WAF")
        assert g.has(listener.arn, KV, EdgeType.REFERENCES, "CERTIFICATE_SECURES")
        assert g.has(APPGW, listener.arn, EdgeType.CONTAINS)
        waf = g.a(WAF)
        assert waf.metadata["detection_only"] is True
        assert waf.metadata["managed_rule_sets"] == ["OWASP 3.2"]
        assert g.has(FDWAF, FD, EdgeType.PROTECTS, "PROTECTED_BY_WAF")

    def test_private_link_visibility(self, g):
        other = "/subscriptions/99999999-9999-9999-9999-999999999999"
        edge = g.edge(other, PLS, EdgeType.GRANTS_ACCESS)
        assert edge.relationship == "POLICY_ALLOWS_ACTION"
        assert edge.properties["auto_approved"] is True and edge.properties["cross_account"] is True

    def test_front_door_rules_and_domains(self, g):
        assert g.has(
            f"{AFD}/ruleSets/rs/rules/override",
            f"{AFD}/originGroups/api",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
        assert g.has(
            f"{AFD}/secrets/cert",
            f"{AFD}/customDomains/shop",
            EdgeType.REFERENCES,
            "CERTIFICATE_SECURES",
        )


class TestGovernance:
    def test_template_specs_and_managed_apps(self, g):
        assert g.a(TS).asset_type == AssetType.PRODUCT_PORTFOLIO
        assert g.has(DEP, TSV, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.has(DEP, VM, EdgeType.MANAGES, "OWNED_BY")
        app = g.a(APP)
        assert app.asset_type == AssetType.PROVISIONED_PRODUCT
        assert g.has(APP, APPDEF, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.has(
            "entra:principal/vendor-ops", APP, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST"
        )
        assert g.has(
            "entra:principal/vendor-def", APPDEF, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST"
        )

    def test_gallery_sharing(self, g):
        other = "/subscriptions/88888888-8888-8888-8888-888888888888"
        assert g.has(other, GAL, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST")
        assert g.has(IMGV, VM, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.a(IMGV).metadata["target_regions"] == ["West Europe", "East US"]

    def test_placement_groups_and_b2c(self, g):
        avset = g.a(AVSET)
        assert avset.asset_type == AssetType.PLACEMENT_GROUP
        assert g.has(AVSET, VM, EdgeType.CONTAINS)
        assert g.has(PPG, AVSET, EdgeType.CONTAINS)
        assert g.a(B2C).asset_type == AssetType.USER_POOL

    def test_snapshots_and_disk_export(self, g):
        assert g.a(SNAP).asset_type == AssetType.SNAPSHOT
        assert g.has(DISK, SNAP, EdgeType.REFERENCES, "BACKUP_TO")
        assert g.a(DISK).metadata["export_open"] is True
        assert g.a(SNAP).metadata["export_open"] is False

    def test_dev_center_environment_type(self, g):
        assert g.has(ENVT, SUB_REF, EdgeType.MANAGES, "OWNED_BY")
        assert g.has(
            f"entra:principal/{USER_OID}", ENVT, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION"
        )


class TestDataPlatforms:
    def test_synapse_hdinsight(self, g):
        assert g.has(SYN, ST, EdgeType.REFERENCES, "READS_FROM")
        assert g.has(SNET, SYN, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        assert g.a(f"{SYN}/sqlPools/dw").asset_type == AssetType.DATA_WAREHOUSE
        assert g.has(SNET, HDI, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        assert g.has(HDI, ST, EdgeType.REFERENCES, "READS_FROM")
        assert g.a(HDI).is_internet_exposed

    def test_sql_managed_instance(self, g):
        mi = g.a(MI)
        assert mi.is_internet_exposed and mi.metadata["public_data_endpoint"] is True
        assert g.has(SNET, MI, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        assert g.has(
            f"entra:principal/{USER_OID}", MI, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION"
        )
        assert g.has(MI, MI2, EdgeType.REFERENCES, "REPLICATES_TO")
        assert (
            g.a(f"{P}/Microsoft.Sql/servers/sql/elasticPools/pool").metadata["zone_redundant"]
            is True
        )

    def test_netapp(self, g):
        vol = g.a(NETAPP_VOL)
        assert vol.metadata["open_export"] is True
        assert g.has(NETAPP_VOL, NETAPP_DST, EdgeType.REFERENCES, "REPLICATES_TO")
        assert g.has(NETAPP_VOL, BVAULT, EdgeType.REFERENCES, "BACKUP_TO")
        assert g.has(SNAP_POLICY, NETAPP_VOL, EdgeType.MANAGES, "SCHEDULED_BY")
        assert g.a(SNAP_POLICY).asset_type == AssetType.BACKUP_PLAN

    def test_purview_and_ai_hub(self, g):
        assert g.has(PURVIEW, ST, EdgeType.MANAGES, "OWNED_BY")
        assert not g.a(PURVIEW).is_internet_exposed
        assert g.has(HUBWS, PROJ, EdgeType.CONTAINS)
        assert g.a(COMPUTE).is_internet_exposed
        assert g.has(SNET, COMPUTE, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        conn = g.a(CONNX)
        assert conn.asset_type == AssetType.SOURCE_CONNECTION
        assert "credentials" not in conn.metadata["properties"]


class TestOperations:
    def test_alerts_and_action_groups(self, g):
        assert g.has(MALERT, VM, EdgeType.MONITORS, "MONITORED_BY")
        assert g.has(MALERT, AG, EdgeType.INVOKES, "INVOKES")
        assert g.has(LALERT, LAW, EdgeType.MONITORS, "MONITORED_BY")
        assert g.has(AALERT, SUB_REF, EdgeType.MONITORS, "MONITORED_BY")
        assert g.has(AALERT, AG, EdgeType.INVOKES, "INVOKES")
        assert g.has(SMART, FUNC, EdgeType.MONITORS, "MONITORED_BY")
        assert g.has(AG, FUNC, EdgeType.INVOKES, "INVOKES")
        assert g.has(AG, f"{EH}/eventhubs/alerts", EdgeType.INVOKES, "STREAMS_TO")
        ag = g.a(AG)
        assert ag.metadata["receiver_counts"]["emailReceivers"] == 1
        assert "emailReceivers" not in ag.metadata["properties"]  # contact details dropped
        assert "smsReceivers" not in ag.metadata["properties"]

    def test_arc_and_extensions(self, g):
        assert g.a(ARC).metadata["arc"] is True
        assert g.has(ARC, ARC_EXT, EdgeType.CONTAINS)
        assert g.has(ARC_EXT, LAW, EdgeType.LOGS_TO, "LOGS_TO")

    def test_sentinel_from_solution(self, g):
        sentinel = f"{LAW}/providers/Microsoft.SecurityInsights/onboardingStates/default"
        assert g.a(sentinel).metadata["security_service"] == "sentinel"
        assert g.has(LAW, sentinel, EdgeType.CONTAINS)
        assert g.has(sentinel, SUB_REF, EdgeType.MONITORS, "MONITORED_BY")

    def test_security_automation_and_event_subscription(self, g):
        assert g.has(SECAUTO, f"{EH}/eventhubs/alerts", EdgeType.LOGS_TO, "STREAMS_TO")
        assert g.has(SECAUTO, f"{P}/Microsoft.Logic/workflows/notify", EdgeType.INVOKES, "INVOKES")
        assert g.has(EXT_SUB, FUNC, EdgeType.INVOKES, "INVOKES")
        assert g.has(ST, FUNC, EdgeType.INVOKES, "INVOKES")

    def test_apim_authorization_server(self, g):
        auth = g.a(AUTHS)
        assert auth.asset_type == AssetType.AUTHORIZER
        assert "clientSecret" not in auth.metadata["properties"]


def test_subscription_vending_aliases():
    from cloudg.inventory.azure_hierarchy import discover_azure_hierarchy
    from tests.azure_fakes import FakeArm, TypedFakeGraph

    alias = "/providers/Microsoft.Subscription/aliases/team-a-prod"
    graph = TypedFakeGraph(
        {
            "resourcecontainers": [
                {
                    "id": SUB_REF,
                    "name": "team-a-prod",
                    "type": "microsoft.resources/subscriptions",
                    "subscriptionId": SUB,
                    "properties": {},
                }
            ]
        }
    )
    arm = FakeArm(
        {
            "/providers/Microsoft.Subscription/aliases": [
                {
                    "id": alias,
                    "name": "team-a-prod",
                    "properties": {"subscriptionId": SUB, "provisioningState": "Succeeded"},
                }
            ]
        }
    )
    errors: list[str] = []
    assets = discover_azure_hierarchy(
        object(),
        lambda c: graph,
        include_policies=False,
        errors=errors,
        arm_client_factory=lambda c: arm,
    )
    linker = RelationshipLinker(assets)
    edges = linker.link()
    g = _Graph(assets + linker.external_assets, edges)
    assert g.a(alias).asset_type == AssetType.PROVISIONED_PRODUCT
    assert g.has(alias, SUB_REF, EdgeType.MANAGES, "OWNED_BY")
    assert errors == []
    # no vending rights: nothing mapped, nothing reported
    denied = discover_azure_hierarchy(
        object(),
        lambda c: graph,
        include_policies=False,
        errors=errors,
        arm_client_factory=lambda c: FakeArm({}, forbidden={"/aliases"}),
    )
    assert not any(a.arn == alias for a in denied) and errors == []
