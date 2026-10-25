"""Azure parity: child resources and subscription listings read through ARM REST."""

from __future__ import annotations

import pytest

from cloudg.coverage import ServiceStatus
from cloudg.schema.models import AssetType, EdgeType
from tests.azure_fakes import FakeArm, arm_row, collect_linked
from tests.test_azure_inventory import SUB, _row

SUB_REF = f"/subscriptions/{SUB}"
RG = f"{SUB_REF}/resourceGroups/rg-app"
P = f"{RG}/providers"
NET = f"{P}/Microsoft.Network"

APIM = f"{P}/Microsoft.ApiManagement/service/apim-prod"
FUNC = f"{P}/Microsoft.Web/sites/func-orders"
WEB = f"{P}/Microsoft.Web/sites/web-shop"
SWA = f"{P}/Microsoft.Web/staticSites/swa-portal"
LOGIC = f"{P}/Microsoft.Logic/workflows/la-sync"
CONN = f"{P}/Microsoft.Web/connections/servicebus"
SB = f"{P}/Microsoft.ServiceBus/namespaces/sb-prod"
EH = f"{P}/Microsoft.EventHub/namespaces/eh-prod"
ST = f"{P}/Microsoft.Storage/storageAccounts/stdata"
ST_DR = f"{P}/Microsoft.Storage/storageAccounts/stdatadr"
ASA = f"{P}/Microsoft.StreamAnalytics/streamingjobs/asa-telemetry"
ADF = f"{P}/Microsoft.DataFactory/factories/adf-etl"
SYN = f"{P}/Microsoft.Synapse/workspaces/syn-dw"
SQL = f"{P}/Microsoft.Sql/servers/sql-prod"
SQL_DR = f"{P}/Microsoft.Sql/servers/sql-dr"
SQLDB = f"{SQL}/databases/orders"
SQLDB_DR = f"{SQL_DR}/databases/orders"
COSMOS = f"{P}/Microsoft.DocumentDB/databaseAccounts/cosmos-prod"
ZONE = f"{NET}/dnszones/contoso.com"
PZONE = f"{NET}/privateDnsZones/privatelink.blob.core.windows.net"
PIP = f"{NET}/publicIPAddresses/pip-shop"
PE = f"{NET}/privateEndpoints/pe-stdata"
VNET = f"{NET}/virtualNetworks/vnet-app"
SNET = f"{VNET}/subnets/snet-dns"
RESOLVER = f"{NET}/dnsResolvers/dnspr"
RULESET = f"{NET}/dnsForwardingRulesets/onprem"
WAN = f"{NET}/virtualWans/vwan"
HUB = f"{NET}/virtualHubs/hub-weu"
FW = f"{NET}/azureFirewalls/fw-hub"
AFD = f"{P}/Microsoft.Cdn/profiles/afd-shop"
AFD_EP = f"{AFD}/afdEndpoints/shop"
AFD_OG = f"{AFD}/originGroups/web"
ACR = f"{P}/Microsoft.ContainerRegistry/registries/acrprod"
AKS = f"{P}/Microsoft.ContainerService/managedClusters/aks-prod"
UAMI = f"{P}/Microsoft.ManagedIdentity/userAssignedIdentities/id-orders"
KV = f"{P}/Microsoft.KeyVault/vaults/kv-prod"
TOPIC = f"{P}/Microsoft.EventGrid/systemTopics/kv-events"
OPENAI = f"{P}/Microsoft.CognitiveServices/accounts/oai-prod"
MLW = f"{P}/Microsoft.MachineLearningServices/workspaces/mlw-prod"
SRCH = f"{P}/Microsoft.Search/searchServices/srch-prod"
AA = f"{P}/Microsoft.Automation/automationAccounts/aa-ops"
VM = f"{P}/Microsoft.Compute/virtualMachines/vm-worker"
LAW = f"{P}/Microsoft.OperationalInsights/workspaces/law-sec"
KUSTO = f"{P}/Microsoft.Kusto/clusters/adx-prod"
AMPLS = f"{P}/Microsoft.Insights/privateLinkScopes/ampls"
BATCH = f"{P}/Microsoft.Batch/batchAccounts/batchprod"
DEVC = f"{P}/Microsoft.DevCenter/devcenters/dc"
DEVP = f"{P}/Microsoft.DevCenter/projects/proj"
APPCS = f"{P}/Microsoft.AppConfiguration/configurationStores/appcs"
BVAULT = f"{P}/Microsoft.DataProtection/backupVaults/bv"
SPRING = f"{P}/Microsoft.AppPlatform/Spring/spring"

USER_OID = "bbbb0000-0000-0000-0000-000000000001"
GROUP_OID = "bbbb0000-0000-0000-0000-000000000002"
TENANT = "cccc0000-0000-0000-0000-000000000000"
ISSUER = "https://westeurope.oic.prod-aks.azure.com/tenant/cluster-guid"


def _resources() -> list[dict]:
    return [
        _row(
            APIM,
            "microsoft.apimanagement/service",
            {"gatewayUrl": "https://apim-prod.azure-api.net"},
            sku={"name": "Premium"},
        ),
        _row(
            FUNC,
            "microsoft.web/sites",
            {"defaultHostName": "func-orders.azurewebsites.net"},
            kind="functionapp,linux",
        ),
        _row(
            WEB,
            "microsoft.web/sites",
            {"defaultHostName": "web-shop.azurewebsites.net"},
            kind="app,linux",
        ),
        _row(
            SWA,
            "microsoft.web/staticsites",
            {
                "defaultHostname": "nice-sea.azurestaticapps.net",
                "repositoryUrl": "https://github.com/contoso/portal",
            },
        ),
        _row(
            LOGIC,
            "microsoft.logic/workflows",
            {
                "state": "Enabled",
                "definition": {
                    "triggers": {
                        "every_hour": {
                            "type": "Recurrence",
                            "recurrence": {"frequency": "Hour", "interval": 1},
                        },
                    },
                    "actions": {
                        "send": {
                            "type": "ApiConnection",
                            "inputs": {
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['servicebus']['connectionId']"
                                    }
                                }
                            },
                        },
                        "scope": {
                            "type": "Scope",
                            "actions": {
                                "call_fn": {
                                    "type": "Function",
                                    "inputs": {"function": {"id": f"{FUNC}/functions/process"}},
                                }
                            },
                        },
                        "webhook": {
                            "type": "Http",
                            "inputs": {"uri": "https://hooks.partner.example/notify"},
                        },
                    },
                },
                "parameters": {"$connections": {"value": {"servicebus": {"connectionId": CONN}}}},
            },
        ),
        _row(
            CONN,
            "microsoft.web/connections",
            {
                "api": {
                    "id": f"{SUB_REF}/providers/Microsoft.Web/locations/westeurope/managedApis/servicebus"
                },
                "parameterValues": {"namespaceEndpoint": "sb://sb-prod.servicebus.windows.net/"},
                "authenticatedUser": {"name": "someone@contoso.com"},
            },
        ),
        _row(
            SB,
            "microsoft.servicebus/namespaces",
            {"serviceBusEndpoint": "https://sb-prod.servicebus.windows.net:443/"},
        ),
        _row(EH, "microsoft.eventhub/namespaces", {"kafkaEnabled": True}),
        _row(
            ST,
            "microsoft.storage/storageaccounts",
            {
                "primaryEndpoints": {
                    "blob": "https://stdata.blob.core.windows.net/",
                    "dfs": "https://stdata.dfs.core.windows.net/",
                },
                "isSftpEnabled": True,
            },
            sku={"name": "Standard_RAGRS"},
        ),
        _row(
            ST_DR,
            "microsoft.storage/storageaccounts",
            {"primaryEndpoints": {"blob": "https://stdatadr.blob.core.windows.net/"}},
        ),
        _row(ASA, "microsoft.streamanalytics/streamingjobs", {"jobType": "Cloud"}),
        _row(
            ADF,
            "microsoft.datafactory/factories",
            {
                "repoConfiguration": {
                    "type": "FactoryGitHubConfiguration",
                    "accountName": "contoso",
                    "repositoryName": "etl",
                    "hostName": "",
                },
            },
        ),
        _row(
            SYN,
            "microsoft.synapse/workspaces",
            {
                "connectivityEndpoints": {"dev": "https://syn-dw.dev.azuresynapse.net"},
                "defaultDataLakeStorage": {"accountUrl": "https://stdata.dfs.core.windows.net"},
            },
        ),
        _row(
            SQL,
            "microsoft.sql/servers",
            {"fullyQualifiedDomainName": "sql-prod.database.windows.net"},
        ),
        _row(
            SQL_DR,
            "microsoft.sql/servers",
            {"fullyQualifiedDomainName": "sql-dr.database.windows.net"},
        ),
        _row(SQLDB, "microsoft.sql/servers/databases", {}),
        _row(
            SQLDB_DR,
            "microsoft.sql/servers/databases",
            {"sourceDatabaseId": SQLDB, "secondaryType": "Geo"},
        ),
        _row(
            COSMOS,
            "microsoft.documentdb/databaseaccounts",
            {
                "documentEndpoint": "https://cosmos-prod.documents.azure.com:443/",
                "locations": [
                    {"locationName": "West Europe", "failoverPriority": 0},
                    {"locationName": "North Europe", "failoverPriority": 1},
                ],
            },
            kind="GlobalDocumentDB",
        ),
        _row(ZONE, "microsoft.network/dnszones", {"numberOfRecordSets": 3}),
        _row(PZONE, "microsoft.network/privatednszones", {}),
        _row(PIP, "microsoft.network/publicipaddresses", {"ipAddress": "20.1.2.3"}),
        _row(
            PE,
            "microsoft.network/privateendpoints",
            {
                "customDnsConfigs": [
                    {"fqdn": "stdata.blob.core.windows.net", "ipAddresses": ["10.1.5.4"]}
                ],
                "privateLinkServiceConnections": [
                    {"properties": {"privateLinkServiceId": ST, "groupIds": ["blob"]}}
                ],
            },
        ),
        _row(
            VNET,
            "microsoft.network/virtualnetworks",
            {"subnets": [{"id": SNET, "name": "snet-dns", "properties": {}}]},
        ),
        _row(RESOLVER, "microsoft.network/dnsresolvers", {"virtualNetwork": {"id": VNET}}),
        _row(
            RULESET,
            "microsoft.network/dnsforwardingrulesets",
            {
                "dnsResolverOutboundEndpoints": [{"id": f"{RESOLVER}/outboundEndpoints/out"}],
            },
        ),
        _row(WAN, "microsoft.network/virtualwans", {"virtualHubs": [{"id": HUB}]}),
        _row(
            HUB,
            "microsoft.network/virtualhubs",
            {"virtualWan": {"id": WAN}, "azureFirewall": {"id": FW}},
        ),
        _row(FW, "microsoft.network/azurefirewalls", {"virtualHub": {"id": HUB}}),
        _row(AFD, "microsoft.cdn/profiles", {}, sku={"name": "Premium_AzureFrontDoor"}),
        _row(
            AFD_EP, "microsoft.cdn/profiles/afdendpoints", {"hostName": "shop-abc.z01.azurefd.net"}
        ),
        _row(
            ACR,
            "microsoft.containerregistry/registries",
            {"loginServer": "acrprod.azurecr.io"},
            sku={"name": "Premium"},
        ),
        _row(
            AKS,
            "microsoft.containerservice/managedclusters",
            {
                "oidcIssuerProfile": {"enabled": True, "issuerURL": ISSUER + "/"},
                "aadProfile": {"managed": True, "adminGroupObjectIDs": [GROUP_OID]},
                "securityProfile": {"workloadIdentity": {"enabled": True}},
            },
        ),
        _row(
            UAMI,
            "microsoft.managedidentity/userassignedidentities",
            {"principalId": "p-1", "clientId": "CLIENT-1"},
        ),
        _row(KV, "microsoft.keyvault/vaults", {"vaultUri": "https://kv-prod.vault.azure.net/"}),
        _row(
            TOPIC,
            "microsoft.eventgrid/systemtopics",
            {"source": KV, "topicType": "Microsoft.KeyVault.vaults"},
        ),
        _row(
            f"{TOPIC}/eventSubscriptions/rotate",
            "microsoft.eventgrid/systemtopics/eventsubscriptions",
            {
                "destination": {
                    "endpointType": "AzureFunction",
                    "properties": {"resourceId": f"{FUNC}/functions/rotate"},
                },
                "filter": {"includedEventTypes": ["Microsoft.KeyVault.SecretNearExpiry"]},
            },
        ),
        _row(
            OPENAI,
            "microsoft.cognitiveservices/accounts",
            {"endpoint": "https://oai-prod.openai.azure.com/"},
            kind="OpenAI",
        ),
        _row(MLW, "microsoft.machinelearningservices/workspaces", {}),
        _row(SRCH, "microsoft.search/searchservices", {}),
        _row(AA, "microsoft.automation/automationaccounts", {}),
        _row(
            f"{AA}/runbooks/patch",
            "microsoft.automation/automationaccounts/runbooks",
            {"runbookType": "PowerShell"},
        ),
        _row(VM, "microsoft.compute/virtualmachines", {}),
        _row(LAW, "microsoft.operationalinsights/workspaces", {"customerId": "LAW-1"}),
        _row(
            KUSTO,
            "microsoft.kusto/clusters",
            {"uri": "https://adx-prod.westeurope.kusto.windows.net"},
        ),
        _row(AMPLS, "microsoft.insights/privatelinkscopes", {}),
        _row(BATCH, "microsoft.batch/batchaccounts", {}),
        _row(DEVC, "microsoft.devcenter/devcenters", {}),
        _row(DEVP, "microsoft.devcenter/projects", {"devCenterId": DEVC}),
        _row(APPCS, "microsoft.appconfiguration/configurationstores", {}),
        _row(BVAULT, "microsoft.dataprotection/backupvaults", {}),
        _row(SPRING, "microsoft.appplatform/spring", {}),
    ]


def _routes() -> dict:
    api = f"{APIM}/apis/orders"
    sub = SUB_REF
    return {
        # subscription-level listings
        f"{sub}/providers/Microsoft.Authorization/denyAssignments": [
            arm_row(
                f"{sub}/providers/Microsoft.Authorization/denyAssignments/da1",
                "Microsoft.Authorization/denyAssignments",
                {
                    "denyAssignmentName": "stack deny",
                    "scope": RG,
                    "permissions": [{"actions": ["*/delete"]}],
                    "principals": [{"id": USER_OID, "type": "User"}],
                },
            ),
        ],
        f"{sub}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances": [
            arm_row(
                f"{sub}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/e1",
                "Microsoft.Authorization/roleEligibilityScheduleInstances",
                {
                    "principalId": USER_OID,
                    "principalType": "User",
                    "scope": KV,
                    "roleDefinitionId": "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/00482a5a-887f-4fb3-b363-3b7fe8e74483",
                    "expandedProperties": {
                        "roleDefinition": {"displayName": "Key Vault Administrator"}
                    },
                },
            ),
        ],
        f"{sub}/providers/Microsoft.Authorization/locks": [
            arm_row(
                f"{KV}/providers/Microsoft.Authorization/locks/no-delete",
                "Microsoft.Authorization/locks",
                {"level": "CanNotDelete"},
            ),
        ],
        f"{sub}/providers/Microsoft.ManagedServices/registrationAssignments": [
            arm_row(
                f"{sub}/providers/Microsoft.ManagedServices/registrationAssignments/ra1",
                "Microsoft.ManagedServices/registrationAssignments",
                {
                    "registrationDefinitionId": f"{sub}/providers/Microsoft.ManagedServices/registrationDefinitions/rd1",
                    "registrationDefinition": {
                        "properties": {
                            "registrationDefinitionName": "MSP operations",
                            "managedByTenantId": TENANT,
                            "authorizations": [
                                {
                                    "principalId": "msp-ops",
                                    "roleDefinitionId": "b24988ac-6180-42a0-ab88-20f7382dd24c",
                                }
                            ],
                        }
                    },
                },
            ),
        ],
        f"{sub}/providers/Microsoft.Insights/diagnosticSettings": [
            arm_row(
                f"{sub}/providers/microsoft.insights/diagnosticSettings/activity",
                "Microsoft.Insights/diagnosticSettings",
                {
                    "workspaceId": LAW,
                    "logs": [{"category": "Administrative", "enabled": True}],
                },
            ),
        ],
        f"{sub}/providers/Microsoft.Resources/deployments": [],
        f"{RG}/providers/Microsoft.Resources/deployments": [
            arm_row(
                f"{RG}/providers/Microsoft.Resources/deployments/app-v1",
                "Microsoft.Resources/deployments",
                {
                    "provisioningState": "Succeeded",
                    "outputResources": [{"id": FUNC}, {"id": ST}],
                },
            ),
        ],
        f"{RG}/providers/Microsoft.Resources/deploymentStacks": [
            arm_row(
                f"{RG}/providers/Microsoft.Resources/deploymentStacks/platform",
                "Microsoft.Resources/deploymentStacks",
                {
                    "denySettings": {"mode": "denyDelete"},
                    "resources": [{"id": KV}],
                },
            ),
        ],
        # identity
        f"{UAMI}/federatedIdentityCredentials": [
            arm_row(
                f"{UAMI}/federatedIdentityCredentials/aks",
                "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials",
                {
                    "issuer": ISSUER,
                    "subject": "system:serviceaccount:orders:api",
                    "audiences": ["api://AzureADTokenExchange"],
                },
            ),
            arm_row(
                f"{UAMI}/federatedIdentityCredentials/github",
                "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials",
                {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:contoso/orders:ref:refs/heads/main",
                },
            ),
        ],
        f"{KV}/keys": [
            arm_row(
                f"{KV}/keys/cmk",
                "Microsoft.KeyVault/vaults/keys",
                {
                    "kty": "RSA",
                    "keyUri": "https://kv-prod.vault.azure.net/keys/cmk",
                    "rotationPolicy": {"lifetimeActions": [{"action": {"type": "Rotate"}}]},
                },
            )
        ],
        f"{KV}/secrets": [
            arm_row(
                f"{KV}/secrets/db-password",
                "Microsoft.KeyVault/vaults/secrets",
                {
                    "value": "should-never-be-kept",
                    "attributes": {"enabled": True},
                },
            )
        ],
        # API Management
        f"{APIM}/apis": [
            arm_row(
                api,
                "Microsoft.ApiManagement/service/apis",
                {
                    "displayName": "Orders API",
                    "path": "orders",
                    "serviceUrl": "https://func-orders.azurewebsites.net/api",
                },
            )
        ],
        f"{api}/policies": [
            arm_row(
                f"{api}/policies/policy",
                "Microsoft.ApiManagement/service/apis/policies",
                {
                    "format": "xml",
                    "value": (
                        '<policies><inbound><validate-jwt header-name="Authorization">'
                        '<openid-config url="https://login.microsoftonline.com/t/v2.0/.well-known/openid-configuration" />'
                        '</validate-jwt><set-backend-service backend-id="orders-fn" /></inbound></policies>'
                    ),
                },
            )
        ],
        f"{APIM}/backends": [
            arm_row(
                f"{APIM}/backends/orders-fn",
                "Microsoft.ApiManagement/service/backends",
                {
                    "url": "https://func-orders.azurewebsites.net/api",
                    "resourceId": f"https://management.azure.com{FUNC}",
                    "credentials": {"header": {"x-functions-key": ["{{fn-key}}"]}},
                },
            )
        ],
        f"{APIM}/products": [
            arm_row(
                f"{APIM}/products/starter",
                "Microsoft.ApiManagement/service/products",
                {"displayName": "Starter", "subscriptionRequired": True},
            )
        ],
        f"{APIM}/products/starter/apis": [
            arm_row(
                f"{APIM}/products/starter/apis/orders", "Microsoft.ApiManagement/service/apis", {}
            )
        ],
        f"{APIM}/namedValues": [
            arm_row(
                f"{APIM}/namedValues/fn-key",
                "Microsoft.ApiManagement/service/namedValues",
                {
                    "secret": True,
                    "keyVault": {
                        "secretIdentifier": "https://kv-prod.vault.azure.net/secrets/fn-key"
                    },
                },
            )
        ],
        f"{APIM}/gateways": [
            arm_row(
                f"{APIM}/gateways/onprem",
                "Microsoft.ApiManagement/service/gateways",
                {"locationData": {"name": "DC1"}},
            )
        ],
        # functions and web apps
        f"{FUNC}/functions": [
            arm_row(
                f"{FUNC}/functions/process",
                "Microsoft.Web/sites/functions",
                {
                    "config": {
                        "bindings": [
                            {
                                "type": "serviceBusTrigger",
                                "direction": "in",
                                "name": "msg",
                                "queueName": "orders",
                            },
                            {
                                "type": "eventHub",
                                "direction": "out",
                                "name": "out",
                                "eventHubName": "telemetry",
                            },
                        ]
                    }
                },
            ),
            arm_row(
                f"{FUNC}/functions/nightly",
                "Microsoft.Web/sites/functions",
                {
                    "config": {
                        "bindings": [
                            {
                                "type": "timerTrigger",
                                "direction": "in",
                                "name": "timer",
                                "schedule": "0 0 2 * * *",
                            },
                        ]
                    }
                },
            ),
            arm_row(
                f"{FUNC}/functions/rotate",
                "Microsoft.Web/sites/functions",
                {
                    "config": {
                        "bindings": [
                            {"type": "eventGridTrigger", "direction": "in", "name": "ev"},
                        ]
                    }
                },
            ),
        ],
        f"{FUNC}/config/web": arm_row(
            f"{FUNC}/config/web", "Microsoft.Web/sites/config", {"ftpsState": "Disabled"}
        ),
        f"{WEB}/config/web": arm_row(
            f"{WEB}/config/web",
            "Microsoft.Web/sites/config",
            {
                "linuxFxVersion": "DOCKER|acrprod.azurecr.io/shop:2",
                "ipSecurityRestrictions": [{"action": "Allow", "vnetSubnetResourceId": SNET}],
                "ftpsState": "AllAllowed",
            },
        ),
        f"{WEB}/sourcecontrols/web": arm_row(
            f"{WEB}/sourcecontrols/web",
            "Microsoft.Web/sites/sourcecontrols",
            {
                "repoUrl": "https://github.com/contoso/shop.git",
                "branch": "main",
                "isGitHubAction": True,
            },
        ),
        f"{WEB}/basicPublishingCredentialsPolicies": [
            arm_row(
                f"{WEB}/basicPublishingCredentialsPolicies/scm",
                "Microsoft.Web/sites/basicPublishingCredentialsPolicies",
                {"allow": True},
            ),
        ],
        f"{SWA}/linkedBackends": [
            arm_row(
                f"{SWA}/linkedBackends/api",
                "Microsoft.Web/staticSites/linkedBackends",
                {"backendResourceId": FUNC},
            )
        ],
        # messaging
        f"{SB}/queues": [
            arm_row(
                f"{SB}/queues/orders",
                "Microsoft.ServiceBus/Namespaces/Queues",
                {"forwardDeadLetteredMessagesTo": "orders-dlq"},
            ),
            arm_row(f"{SB}/queues/orders-dlq", "Microsoft.ServiceBus/Namespaces/Queues", {}),
        ],
        f"{SB}/topics": [
            arm_row(f"{SB}/topics/events", "Microsoft.ServiceBus/Namespaces/Topics", {})
        ],
        f"{SB}/topics/events/subscriptions": [
            arm_row(
                f"{SB}/topics/events/subscriptions/to-orders",
                "Microsoft.ServiceBus/Namespaces/Topics/Subscriptions",
                {"forwardTo": "orders"},
            )
        ],
        f"{EH}/eventhubs": [
            arm_row(
                f"{EH}/eventhubs/telemetry",
                "Microsoft.EventHub/Namespaces/EventHubs",
                {
                    "partitionCount": 4,
                    "captureDescription": {
                        "enabled": True,
                        "destination": {
                            "properties": {
                                "storageAccountResourceId": ST,
                                "blobContainer": "capture",
                            }
                        },
                    },
                },
            )
        ],
        f"{ASA}/inputs": [
            arm_row(
                f"{ASA}/inputs/telemetry",
                "Microsoft.StreamAnalytics/streamingjobs/inputs",
                {
                    "datasource": {
                        "type": "Microsoft.ServiceBus/EventHub",
                        "properties": {
                            "serviceBusNamespace": "eh-prod",
                            "eventHubName": "telemetry",
                        },
                    },
                },
            )
        ],
        f"{ASA}/outputs": [
            arm_row(
                f"{ASA}/outputs/sql",
                "Microsoft.StreamAnalytics/streamingjobs/outputs",
                {
                    "datasource": {
                        "type": "Microsoft.Sql/Server/Database",
                        "properties": {"server": "sql-prod", "database": "orders"},
                    },
                },
            )
        ],
        # Data Factory
        f"{ADF}/linkedservices": [
            arm_row(
                f"{ADF}/linkedservices/blob",
                "Microsoft.DataFactory/factories/linkedservices",
                {
                    "type": "AzureBlobStorage",
                    "typeProperties": {
                        "connectionString": "DefaultEndpointsProtocol=https;AccountName=stdata;AccountKey=SECRET"
                    },
                    "connectVia": {"referenceName": "shir", "type": "IntegrationRuntimeReference"},
                },
            ),
            arm_row(
                f"{ADF}/linkedservices/sql",
                "Microsoft.DataFactory/factories/linkedservices",
                {
                    "type": "AzureSqlDatabase",
                    "typeProperties": {
                        "connectionString": "Server=tcp:sql-prod.database.windows.net,1433;Database=orders"
                    },
                },
            ),
        ],
        f"{ADF}/datasets": [
            arm_row(
                f"{ADF}/datasets/raw",
                "Microsoft.DataFactory/factories/datasets",
                {"linkedServiceName": {"referenceName": "blob"}, "type": "DelimitedText"},
            ),
            arm_row(
                f"{ADF}/datasets/orders",
                "Microsoft.DataFactory/factories/datasets",
                {"linkedServiceName": {"referenceName": "sql"}, "type": "AzureSqlTable"},
            ),
        ],
        f"{ADF}/integrationRuntimes": [
            arm_row(
                f"{ADF}/integrationruntimes/shir",
                "Microsoft.DataFactory/factories/integrationruntimes",
                {"type": "SelfHosted"},
            )
        ],
        f"{ADF}/pipelines": [
            arm_row(
                f"{ADF}/pipelines/load",
                "Microsoft.DataFactory/factories/pipelines",
                {
                    "activities": [
                        {
                            "name": "copy",
                            "type": "Copy",
                            "inputs": [{"referenceName": "raw"}],
                            "outputs": [{"referenceName": "orders"}],
                        },
                        {
                            "name": "loop",
                            "type": "ForEach",
                            "typeProperties": {
                                "activities": [
                                    {
                                        "name": "notify",
                                        "type": "WebActivity",
                                        "typeProperties": {
                                            "url": "https://hooks.partner.example/done"
                                        },
                                    },
                                ]
                            },
                        },
                    ]
                },
            )
        ],
        f"{ADF}/triggers": [
            arm_row(
                f"{ADF}/triggers/nightly",
                "Microsoft.DataFactory/factories/triggers",
                {
                    "type": "ScheduleTrigger",
                    "runtimeState": "Started",
                    "pipelines": [{"pipelineReference": {"referenceName": "load"}}],
                },
            )
        ],
        # SQL and Cosmos
        f"{SQL}/failoverGroups": [
            arm_row(
                f"{SQL}/failoverGroups/fog",
                "Microsoft.Sql/servers/failoverGroups",
                {
                    "partnerServers": [{"id": SQL_DR, "replicationRole": "Secondary"}],
                    "databases": [SQLDB],
                },
            )
        ],
        f"{SQL}/auditingSettings": [
            arm_row(
                f"{SQL}/auditingSettings/default",
                "Microsoft.Sql/servers/auditingSettings",
                {
                    "state": "Enabled",
                    "storageEndpoint": "https://stdata.blob.core.windows.net/",
                },
            )
        ],
        f"{COSMOS}/sqlRoleAssignments": [
            arm_row(
                f"{COSMOS}/sqlRoleAssignments/ra1",
                "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments",
                {
                    "principalId": USER_OID,
                    "roleDefinitionId": f"{COSMOS}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002",
                    "scope": COSMOS,
                },
            )
        ],
        # storage
        f"{ST}/objectReplicationPolicies": [
            arm_row(
                f"{ST}/objectReplicationPolicies/default",
                "Microsoft.Storage/storageAccounts/objectReplicationPolicies",
                {
                    "sourceAccount": ST,
                    "destinationAccount": ST_DR,
                    "rules": [{"sourceContainer": "raw", "destinationContainer": "raw"}],
                },
            )
        ],
        f"{ST}/localUsers": [
            arm_row(
                f"{ST}/localUsers/partner",
                "Microsoft.Storage/storageAccounts/localUsers",
                {
                    "hasSshKey": True,
                    "homeDirectory": "inbox",
                    "permissionScopes": [
                        {"service": "blob", "resourceName": "inbox", "permissions": "rcw"}
                    ],
                    "sshAuthorizedKeys": [{"key": "ssh-rsa AAAA"}],
                },
            )
        ],
        f"{ST}/blobServices/default": arm_row(
            f"{ST}/blobServices/default",
            "Microsoft.Storage/storageAccounts/blobServices",
            {
                "isVersioningEnabled": True,
                "deleteRetentionPolicy": {"enabled": True, "days": 7},
            },
        ),
        # DNS
        f"{ZONE}/all": [
            arm_row(
                f"{ZONE}/A/www",
                "Microsoft.Network/dnszones/A",
                {"fqdn": "www.contoso.com.", "TTL": 300, "targetResource": {"id": PIP}},
            ),
            arm_row(
                f"{ZONE}/CNAME/api",
                "Microsoft.Network/dnszones/CNAME",
                {"fqdn": "api.contoso.com.", "CNAMERecord": {"cname": "apim-prod.azure-api.net"}},
            ),
            arm_row(
                f"{ZONE}/A/legacy",
                "Microsoft.Network/dnszones/A",
                {"fqdn": "legacy.contoso.com.", "ARecords": [{"ipv4Address": "20.1.2.3"}]},
            ),
        ],
        f"{PZONE}/ALL": [
            arm_row(
                f"{PZONE}/A/stdata",
                "Microsoft.Network/privateDnsZones/A",
                {
                    "fqdn": "stdata.privatelink.blob.core.windows.net.",
                    "aRecords": [{"ipv4Address": "10.1.5.4"}],
                },
            ),
        ],
        f"{RESOLVER}/inboundEndpoints": [
            arm_row(
                f"{RESOLVER}/inboundEndpoints/in",
                "Microsoft.Network/dnsResolvers/inboundEndpoints",
                {
                    "ipConfigurations": [{"subnet": {"id": SNET}, "privateIpAddress": "10.1.9.4"}],
                },
            )
        ],
        f"{RESOLVER}/outboundEndpoints": [
            arm_row(
                f"{RESOLVER}/outboundEndpoints/out",
                "Microsoft.Network/dnsResolvers/outboundEndpoints",
                {"subnet": {"id": SNET}},
            )
        ],
        f"{RULESET}/forwardingRules": [
            arm_row(
                f"{RULESET}/forwardingRules/corp",
                "Microsoft.Network/dnsForwardingRulesets/forwardingRules",
                {
                    "domainName": "corp.contoso.com.",
                    "targetDnsServers": [{"ipAddress": "10.1.9.4", "port": 53}],
                },
            )
        ],
        f"{RULESET}/virtualNetworkLinks": [
            arm_row(
                f"{RULESET}/virtualNetworkLinks/app",
                "Microsoft.Network/dnsForwardingRulesets/virtualNetworkLinks",
                {"virtualNetwork": {"id": VNET}},
            )
        ],
        # Virtual WAN
        f"{HUB}/hubVirtualNetworkConnections": [
            arm_row(
                f"{HUB}/hubVirtualNetworkConnections/app",
                "Microsoft.Network/virtualHubs/hubVirtualNetworkConnections",
                {
                    "remoteVirtualNetwork": {"id": VNET},
                    "enableInternetSecurity": True,
                },
            )
        ],
        f"{HUB}/routingIntent": [
            arm_row(
                f"{HUB}/routingIntent/intent",
                "Microsoft.Network/virtualHubs/routingIntent",
                {
                    "routingPolicies": [
                        {"name": "Internet", "destinations": ["Internet"], "nextHop": FW}
                    ],
                },
            )
        ],
        f"{HUB}/hubRouteTables": [
            arm_row(
                f"{HUB}/hubRouteTables/defaultRouteTable",
                "Microsoft.Network/virtualHubs/hubRouteTables",
                {
                    "routes": [
                        {
                            "name": "all",
                            "destinationType": "CIDR",
                            "destinations": ["0.0.0.0/0"],
                            "nextHopType": "ResourceId",
                            "nextHop": FW,
                        }
                    ],
                },
            )
        ],
        # Front Door
        f"{AFD_EP}/routes": [
            arm_row(
                f"{AFD_EP}/routes/default",
                "Microsoft.Cdn/profiles/afdEndpoints/routes",
                {
                    "originGroup": {"id": AFD_OG},
                    "patternsToMatch": ["/*"],
                    "httpsRedirect": "Enabled",
                },
            )
        ],
        f"{AFD}/afdEndpoints": [
            arm_row(
                AFD_EP,
                "Microsoft.Cdn/profiles/afdEndpoints",
                {"hostName": "shop-abc.z01.azurefd.net"},
            )
        ],
        f"{AFD}/originGroups": [arm_row(AFD_OG, "Microsoft.Cdn/profiles/originGroups", {})],
        f"{AFD_OG}/origins": [
            arm_row(
                f"{AFD_OG}/origins/web",
                "Microsoft.Cdn/profiles/originGroups/origins",
                {"hostName": "web-shop.azurewebsites.net"},
            )
        ],
        f"{AFD}/secrets": [
            arm_row(
                f"{AFD}/secrets/cert",
                "Microsoft.Cdn/profiles/secrets",
                {
                    "parameters": {
                        "type": "CustomerCertificate",
                        "secretSource": {"id": f"{KV}/secrets/shop-cert"},
                    },
                },
            )
        ],
        # containers
        f"{ACR}/replications": [
            arm_row(
                f"{ACR}/replications/northeurope",
                "Microsoft.ContainerRegistry/registries/replications",
                {},
                location="northeurope",
            )
        ],
        f"{ACR}/webhooks": [
            arm_row(
                f"{ACR}/webhooks/deploy",
                "Microsoft.ContainerRegistry/registries/webhooks",
                {"actions": ["push"]},
            )
        ],
        f"{ACR}/tasks": [
            arm_row(
                f"{ACR}/tasks/build",
                "Microsoft.ContainerRegistry/registries/tasks",
                {
                    "step": {"contextPath": "https://github.com/contoso/shop.git"},
                    "trigger": {"timerTriggers": [{"schedule": "0 1 * * *"}]},
                },
            )
        ],
        f"{ACR}/tokens": [
            arm_row(
                f"{ACR}/tokens/ci",
                "Microsoft.ContainerRegistry/registries/tokens",
                {"scopeMapId": f"{ACR}/scopeMaps/push"},
            )
        ],
        f"{ACR}/scopeMaps": [
            arm_row(
                f"{ACR}/scopeMaps/push",
                "Microsoft.ContainerRegistry/registries/scopeMaps",
                {"actions": ["repositories/shop/content/write"]},
            )
        ],
        f"{AKS}/trustedAccessRoleBindings": [
            arm_row(
                f"{AKS}/trustedAccessRoleBindings/backup",
                "Microsoft.ContainerService/managedClusters/trustedAccessRoleBindings",
                {
                    "sourceResourceId": BVAULT,
                    "roles": ["Microsoft.DataProtection/backupVaults/backup-operator"],
                },
            )
        ],
        # AI and ML
        f"{OPENAI}/deployments": [
            arm_row(
                f"{OPENAI}/deployments/gpt4o",
                "Microsoft.CognitiveServices/accounts/deployments",
                {
                    "model": {"format": "OpenAI", "name": "gpt-4o", "version": "2024-08-06"},
                    "raiPolicyName": "strict",
                },
                sku={"name": "GlobalStandard", "capacity": 50},
            )
        ],
        f"{OPENAI}/raiPolicies": [
            arm_row(
                f"{OPENAI}/raiPolicies/strict",
                "Microsoft.CognitiveServices/accounts/raiPolicies",
                {
                    "mode": "Blocking",
                    "contentFilters": [
                        {"name": "hate", "blocking": True, "enabled": True, "source": "Prompt"}
                    ],
                },
            )
        ],
        f"{MLW}/datastores": [
            arm_row(
                f"{MLW}/datastores/raw",
                "Microsoft.MachineLearningServices/workspaces/datastores",
                {
                    "datastoreType": "AzureBlob",
                    "accountName": "stdata",
                    "containerName": "raw",
                    "credentials": {"credentialsType": "AccountKey", "secrets": {"key": "x"}},
                },
            )
        ],
        f"{MLW}/onlineEndpoints": [
            arm_row(
                f"{MLW}/onlineEndpoints/score",
                "Microsoft.MachineLearningServices/workspaces/onlineEndpoints",
                {
                    "scoringUri": "https://score.westeurope.inference.ml.azure.com/score",
                    "authMode": "Key",
                    "publicNetworkAccess": "Enabled",
                },
            )
        ],
        f"{MLW}/onlineEndpoints/score/deployments": [
            arm_row(
                f"{MLW}/onlineEndpoints/score/deployments/blue",
                "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments",
                {"instanceType": "Standard_DS3_v2"},
            )
        ],
        f"{SRCH}/sharedPrivateLinkResources": [
            arm_row(
                f"{SRCH}/sharedPrivateLinkResources/blob",
                "Microsoft.Search/searchServices/sharedPrivateLinkResources",
                {
                    "privateLinkResourceId": ST,
                    "groupId": "blob",
                    "status": "Approved",
                },
            )
        ],
        # operations
        f"{AA}/schedules": [
            arm_row(
                f"{AA}/schedules/nightly",
                "Microsoft.Automation/automationAccounts/schedules",
                {"frequency": "Day", "interval": 1},
            )
        ],
        f"{AA}/jobSchedules": [
            arm_row(
                f"{AA}/jobSchedules/js1",
                "Microsoft.Automation/automationAccounts/jobSchedules",
                {
                    "runbook": {"name": "patch"},
                    "schedule": {"name": "nightly"},
                    "runOn": "workers",
                },
            )
        ],
        f"{AA}/hybridRunbookWorkerGroups": [
            arm_row(
                f"{AA}/hybridRunbookWorkerGroups/workers",
                "Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups",
                {"groupType": "User"},
            )
        ],
        f"{AA}/hybridRunbookWorkerGroups/workers/hybridRunbookWorkers": [
            arm_row(
                f"{AA}/hybridRunbookWorkerGroups/workers/hybridRunbookWorkers/w1",
                "Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/hybridRunbookWorkers",
                {"vmResourceId": VM},
            )
        ],
        f"{AA}/softwareUpdateConfigurations": [
            arm_row(
                f"{AA}/softwareUpdateConfigurations/monthly",
                "Microsoft.Automation/automationAccounts/softwareUpdateConfigurations",
                {
                    "updateConfiguration": {"azureVirtualMachines": [VM]},
                },
            )
        ],
        f"{KUSTO}/databases": [
            arm_row(f"{KUSTO}/databases/telemetry", "Microsoft.Kusto/clusters/databases", {})
        ],
        f"{KUSTO}/databases/telemetry/dataConnections": [
            arm_row(
                f"{KUSTO}/databases/telemetry/dataConnections/eh",
                "Microsoft.Kusto/clusters/databases/dataConnections",
                {
                    "eventHubResourceId": f"{EH}/eventhubs/telemetry",
                },
                kind="EventHub",
            )
        ],
        f"{KUSTO}/principalAssignments": [
            arm_row(
                f"{KUSTO}/principalAssignments/admins",
                "Microsoft.Kusto/clusters/principalAssignments",
                {
                    "principalId": GROUP_OID,
                    "principalType": "Group",
                    "role": "AllDatabasesAdmin",
                },
            )
        ],
        f"{AMPLS}/scopedResources": [
            arm_row(
                f"{AMPLS}/scopedResources/law",
                "Microsoft.Insights/privateLinkScopes/scopedResources",
                {"linkedResourceId": LAW},
            )
        ],
        f"{BATCH}/pools": [
            arm_row(
                f"{BATCH}/pools/render",
                "Microsoft.Batch/batchAccounts/pools",
                {
                    "vmSize": "STANDARD_D4",
                    "networkConfiguration": {
                        "subnetId": SNET,
                        "publicIPAddressConfiguration": {"provision": "NoPublicIPAddresses"},
                    },
                },
            )
        ],
        f"{SPRING}/apps": [
            arm_row(
                f"{SPRING}/apps/gateway",
                "Microsoft.AppPlatform/Spring/apps",
                {"public": True, "url": "https://spring-gateway.azuremicroservices.io"},
            )
        ],
        f"{DEVC}/catalogs": [
            arm_row(
                f"{DEVC}/catalogs/envs",
                "Microsoft.DevCenter/devcenters/catalogs",
                {"gitHub": {"uri": "https://github.com/contoso/envs.git", "branch": "main"}},
            )
        ],
        f"{DEVP}/environmentTypes": [
            arm_row(
                f"{DEVP}/environmentTypes/dev",
                "Microsoft.DevCenter/projects/environmentTypes",
                {"deploymentTargetId": SUB_REF},
            )
        ],
        f"{APPCS}/replicas": [
            arm_row(
                f"{APPCS}/replicas/neu",
                "Microsoft.AppConfiguration/configurationStores/replicas",
                {"endpoint": "https://appcs-neu.azconfig.io"},
            )
        ],
        f"{BVAULT}/backupPolicies": [
            arm_row(
                f"{BVAULT}/backupPolicies/blob",
                "Microsoft.DataProtection/backupVaults/backupPolicies",
                {"datasourceTypes": ["Microsoft.Storage/storageAccounts/blobServices"]},
            )
        ],
        # Sentinel
        f"{LAW}/providers/Microsoft.SecurityInsights/onboardingStates": [
            arm_row(
                f"{LAW}/providers/Microsoft.SecurityInsights/onboardingStates/default",
                "Microsoft.SecurityInsights/onboardingStates",
                {},
            )
        ],
        f"{LAW}/providers/Microsoft.SecurityInsights/dataConnectors": [
            arm_row(
                f"{LAW}/providers/Microsoft.SecurityInsights/dataConnectors/asc",
                "Microsoft.SecurityInsights/dataConnectors",
                {"subscriptionId": SUB},
                kind="AzureSecurityCenter",
            ),
            arm_row(
                f"{LAW}/providers/Microsoft.SecurityInsights/dataConnectors/aws",
                "Microsoft.SecurityInsights/dataConnectors",
                {"awsRoleArn": "arn:aws:iam::123456789012:role/SentinelReader"},
                kind="AmazonWebServicesCloudTrail",
            ),
        ],
        f"{LAW}/providers/Microsoft.SecurityInsights/alertRules": [
            arm_row(
                f"{LAW}/providers/Microsoft.SecurityInsights/alertRules/r1",
                "Microsoft.SecurityInsights/alertRules",
                {"displayName": "Brute force", "enabled": True, "severity": "High"},
                kind="Scheduled",
            )
        ],
        f"{LAW}/providers/Microsoft.SecurityInsights/automationRules": [
            arm_row(
                f"{LAW}/providers/Microsoft.SecurityInsights/automationRules/a1",
                "Microsoft.SecurityInsights/automationRules",
                {
                    "displayName": "Isolate",
                    "actions": [
                        {
                            "actionType": "RunPlaybook",
                            "actionConfiguration": {"logicAppResourceId": LOGIC},
                        }
                    ],
                },
            )
        ],
        # diagnostic settings
        f"{KV}/providers/Microsoft.Insights/diagnosticSettings": [
            arm_row(
                f"{KV}/providers/microsoft.insights/diagnosticSettings/audit",
                "Microsoft.Insights/diagnosticSettings",
                {
                    "workspaceId": LAW,
                    "eventHubAuthorizationRuleId": f"{EH}/authorizationRules/RootManageSharedAccessKey",
                    "eventHubName": "telemetry",
                    "logs": [{"categoryGroup": "audit", "enabled": True}],
                },
            )
        ],
        f"{OPENAI}/providers/Microsoft.Insights/diagnosticSettings": [
            arm_row(
                f"{OPENAI}/providers/microsoft.insights/diagnosticSettings/req",
                "Microsoft.Insights/diagnosticSettings",
                {
                    "storageAccountId": ST,
                    "logs": [{"category": "RequestResponse", "enabled": True}],
                },
            )
        ],
    }


class _SearchPlane(FakeArm):
    pass


def _dataplane(credential, base_url, scope):
    if "search.windows.net" in base_url:
        return FakeArm(
            {
                "/datasources": [
                    {
                        "name": "docs",
                        "type": "azureblob",
                        "credentials": {"connectionString": "ResourceId=" + ST + ";"},
                        "container": {"name": "docs"},
                    }
                ],
                "/indexers": [
                    {
                        "name": "docs-indexer",
                        "dataSourceName": "docs",
                        "targetIndexName": "docs-index",
                        "skillsetName": "enrich",
                        "schedule": {"interval": "PT1H"},
                    }
                ],
                "/indexes": [
                    {
                        "name": "docs-index",
                        "fields": [{"name": "id"}],
                        "vectorSearch": {
                            "vectorizers": [
                                {
                                    "azureOpenAIParameters": {
                                        "resourceUri": "https://oai-prod.openai.azure.com"
                                    }
                                }
                            ]
                        },
                    }
                ],
                "/skillsets": [
                    {
                        "name": "enrich",
                        "skills": [
                            {
                                "@odata.type": "#Microsoft.Skills.Custom.WebApiSkill",
                                "uri": "https://func-orders.azurewebsites.net/api/enrich",
                            }
                        ],
                    }
                ],
            }
        )
    if "azuresynapse.net" in base_url:
        return FakeArm(
            {
                "/pipelines": [
                    {
                        "name": "ingest",
                        "id": f"{SYN}/pipelines/ingest",
                        "properties": {
                            "activities": [
                                {
                                    "name": "copy",
                                    "type": "Copy",
                                    "inputs": [{"referenceName": "lake"}],
                                    "outputs": [],
                                }
                            ]
                        },
                    }
                ],
                "/datasets": [
                    {
                        "name": "lake",
                        "id": f"{SYN}/datasets/lake",
                        "properties": {"linkedServiceName": {"referenceName": "adls"}},
                    }
                ],
                "/linkedservices": [
                    {
                        "name": "adls",
                        "id": f"{SYN}/linkedservices/adls",
                        "properties": {
                            "type": "AzureBlobFS",
                            "typeProperties": {"url": "https://stdata.dfs.core.windows.net"},
                        },
                    }
                ],
                "/triggers": [],
            }
        )
    return FakeArm({})


@pytest.fixture(scope="module")
def mapped():
    return collect_linked(
        {
            "resources": _resources(),
            "resourcecontainers": [
                {
                    "id": RG,
                    "name": "rg-app",
                    "type": "microsoft.resources/subscriptions/resourcegroups",
                    "subscriptionId": SUB,
                    "properties": {},
                },
            ],
        },
        _routes(),
        dataplane=_dataplane,
    )


class TestGovernanceListings:
    def test_deny_assignments_and_locks(self, mapped):
        g = mapped.graph
        deny = f"{SUB_REF}/providers/Microsoft.Authorization/denyAssignments/da1"
        assert g.a(deny).asset_type == AssetType.GUARDRAIL
        assert g.has(deny, RG, EdgeType.GOVERNS, "POLICY_DENIES_ACTION")
        assert g.has(
            f"entra:principal/{USER_OID}", deny, EdgeType.REFERENCES, "PERMISSION_BOUNDARY_LIMITS"
        )
        lock = f"{KV}/providers/Microsoft.Authorization/locks/no-delete"
        assert g.a(lock).metadata["lock_level"] == "CanNotDelete"
        assert g.has(lock, KV, EdgeType.GOVERNS, "POLICY_DENIES_ACTION")

    def test_pim_eligible_rbac(self, mapped):
        g = mapped.graph
        edge = g.edge(f"entra:principal/{USER_OID}", KV, EdgeType.GRANTS_ACCESS)
        assert edge.relationship == "POLICY_ALLOWS_ACTION"
        assert edge.properties["eligible"] is True
        assert edge.properties["role"] == "Key Vault Administrator"
        assert edge.properties["privileged"] is True
        assert mapped.coverage["pim_eligibility"].status == ServiceStatus.SUCCESS

    def test_lighthouse(self, mapped):
        g = mapped.graph
        ra = f"{SUB_REF}/providers/Microsoft.ManagedServices/registrationAssignments/ra1"
        asset = g.a(ra)
        assert asset.asset_type == AssetType.RESOURCE_SHARE
        assert asset.metadata["managed_by_tenant_id"] == TENANT
        assert g.has(ra, SUB_REF, EdgeType.GRANTS_ACCESS, "CROSS_ACCOUNT_TRUST")
        assert g.has("entra:principal/msp-ops", ra, EdgeType.ASSUMES_ROLE, "CROSS_ACCOUNT_TRUST")

    def test_deployments_stacks_activity_log(self, mapped):
        g = mapped.graph
        dep = f"{RG}/providers/Microsoft.Resources/deployments/app-v1"
        assert g.a(dep).asset_type == AssetType.IAC_STACK
        assert g.has(dep, FUNC, EdgeType.MANAGES, "OWNED_BY")
        stack = f"{RG}/providers/Microsoft.Resources/deploymentStacks/platform"
        assert g.has(stack, KV, EdgeType.MANAGES, "OWNED_BY")
        assert g.has(stack, KV, EdgeType.GOVERNS, "POLICY_DENIES_ACTION")
        diag = f"{SUB_REF}/providers/microsoft.insights/diagnosticSettings/activity"
        assert g.a(diag).metadata["activity_log_export"] is True
        assert g.has(diag, LAW, EdgeType.LOGS_TO, "LOGS_TO")
        assert g.has(diag, SUB_REF, EdgeType.MONITORS, "MONITORED_BY")


class TestIdentity:
    def test_federated_credentials(self, mapped):
        g = mapped.graph
        aks_fic = f"{UAMI}/federatedIdentityCredentials/aks"
        gh_fic = f"{UAMI}/federatedIdentityCredentials/github"
        assert g.a(aks_fic).asset_type == AssetType.IDENTITY_PROVIDER
        assert g.has(aks_fic, UAMI, EdgeType.IAM_TRUST, "ROLE_ASSUMES_ROLE")
        assert g.has(gh_fic, UAMI, EdgeType.IAM_TRUST, "CROSS_ACCOUNT_TRUST")
        # the AKS OIDC issuer resolves to the cluster: cluster -> identity trust
        assert g.has(AKS, UAMI, EdgeType.IAM_TRUST, "ROLE_ASSUMES_ROLE")

    def test_aks_admin_group_and_trusted_access(self, mapped):
        g = mapped.graph
        assert g.has(
            f"entra:principal/{GROUP_OID}", AKS, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION"
        )
        assert g.a(AKS).metadata["workload_identity"] is True
        assert g.has(BVAULT, AKS, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION")

    def test_key_vault_items_and_rotation(self, mapped):
        g = mapped.graph
        key = g.a(f"{KV}/keys/cmk")
        assert key.asset_type == AssetType.KMS_KEY and key.metadata["auto_rotation"] is True
        secret = g.a(f"{KV}/secrets/db-password")
        assert secret.asset_type == AssetType.SECRET
        assert "value" not in secret.metadata["properties"]
        # Event Grid near-expiry subscription: the vault rotates through the function
        assert g.has(KV, f"{FUNC}/functions/rotate", EdgeType.INVOKES, "ROTATES_SECRET")


class TestApiManagement:
    def test_apis_backends_products(self, mapped):
        g = mapped.graph
        api = f"{APIM}/apis/orders"
        backend = f"{APIM}/backends/orders-fn"
        assert g.a(api).asset_type == AssetType.API_GATEWAY
        assert g.has(APIM, api, EdgeType.CONTAINS)
        assert g.has(api, FUNC, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert g.has(backend, FUNC, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert "credentials" not in g.a(backend).metadata["properties"]
        assert g.has(api, backend, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert g.has(f"{APIM}/products/starter", api, EdgeType.REFERENCES, "DEPENDS_ON")
        assert f"{APIM}/products/starter/apis/orders".lower() not in g.by_arn

    def test_jwt_authorizer_and_named_values(self, mapped):
        g = mapped.graph
        api = f"{APIM}/apis/orders"
        auth = g.a(f"{api}/authorizers/jwt")
        assert auth.asset_type == AssetType.AUTHORIZER
        assert g.has(api, auth.arn, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.a(api).metadata["jwt_validation"][0]["openid_hosts"] == [
            "login.microsoftonline.com"
        ]
        nv = f"{APIM}/namedValues/fn-key"
        assert g.a(nv).asset_type == AssetType.PARAMETER
        assert g.has(nv, KV, EdgeType.REFERENCES, "READS_FROM")
        assert g.a(f"{APIM}/gateways/onprem").metadata["self_hosted"] is True


class TestServerlessAndIntegration:
    def test_function_bindings(self, mapped):
        g = mapped.graph
        fn = f"{FUNC}/functions/process"
        assert g.a(fn).asset_type == AssetType.CLOUD_FUNCTION
        assert g.has(f"{SB}/queues/orders", fn, EdgeType.INVOKES, "TRIGGERED_BY")
        assert g.has(fn, f"{EH}/eventhubs/telemetry", EdgeType.REFERENCES, "WRITES_TO")
        timer = f"{FUNC}/functions/nightly/timers/timer"
        assert g.a(timer).asset_type == AssetType.SCHEDULE
        assert g.has(timer, f"{FUNC}/functions/nightly", EdgeType.MANAGES, "SCHEDULED_BY")

    def test_service_bus_and_event_hubs(self, mapped):
        g = mapped.graph
        assert g.a(f"{SB}/queues/orders").asset_type == AssetType.MESSAGE_QUEUE
        assert g.has(
            f"{SB}/queues/orders", f"{SB}/queues/orders-dlq", EdgeType.REFERENCES, "WRITES_TO"
        )
        sub = f"{SB}/topics/events/subscriptions/to-orders"
        assert g.has(f"{SB}/topics/events", sub, EdgeType.CONTAINS)
        assert g.has(sub, f"{SB}/queues/orders", EdgeType.REFERENCES, "WRITES_TO")
        assert g.has(f"{EH}/eventhubs/telemetry", ST, EdgeType.LOGS_TO, "STREAMS_TO")
        assert g.a(EH).metadata["kafka_enabled"] is True

    def test_logic_app_and_connection(self, mapped):
        g = mapped.graph
        assert g.has(LOGIC, CONN, EdgeType.INVOKES, "INVOKES")
        assert g.has(LOGIC, f"{FUNC}/functions/process", EdgeType.INVOKES, "INVOKES")
        trig = f"{LOGIC}/triggers/every_hour"
        assert g.has(trig, LOGIC, EdgeType.MANAGES, "SCHEDULED_BY")
        conn = g.a(CONN)
        assert conn.asset_type == AssetType.SOURCE_CONNECTION
        assert g.has(CONN, SB, EdgeType.REFERENCES, "DEPENDS_ON")
        assert "authenticatedUser" not in conn.metadata["properties"]

    def test_stream_analytics(self, mapped):
        g = mapped.graph
        assert g.has(ASA, f"{EH}/eventhubs/telemetry", EdgeType.REFERENCES, "READS_FROM")
        assert g.has(ASA, SQL, EdgeType.REFERENCES, "WRITES_TO")

    def test_web_app_depth(self, mapped):
        g = mapped.graph
        repo = "repo:https://github.com/contoso/shop"
        assert g.has(WEB, repo, EdgeType.REFERENCES, "READS_FROM")
        assert g.has(WEB, ACR, EdgeType.USES_IMAGE, "RUNS_ON")
        assert g.has(SNET, WEB, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION")
        web = g.a(WEB)
        assert web.metadata["ftps_state"] == "AllAllowed" and web.metadata["basic_auth_scm"] is True
        assert g.has(SWA, FUNC, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert g.has(
            SWA, "repo:https://github.com/contoso/portal", EdgeType.REFERENCES, "READS_FROM"
        )


class TestData:
    def test_data_factory(self, mapped):
        g = mapped.graph
        pipe = f"{ADF}/pipelines/load"
        assert g.a(pipe).asset_type == AssetType.ETL_JOB
        assert g.has(pipe, f"{ADF}/datasets/raw", EdgeType.REFERENCES, "READS_FROM")
        assert g.has(pipe, f"{ADF}/datasets/orders", EdgeType.REFERENCES, "WRITES_TO")
        assert g.has(
            f"{ADF}/datasets/raw", f"{ADF}/linkedservices/blob", EdgeType.REFERENCES, "DEPENDS_ON"
        )
        blob_ls = g.a(f"{ADF}/linkedservices/blob")
        assert g.has(blob_ls.arn, ST, EdgeType.REFERENCES, "DEPENDS_ON")
        assert "typeProperties" not in blob_ls.metadata["properties"]  # connection strings dropped
        assert g.has(blob_ls.arn, f"{ADF}/integrationruntimes/shir", EdgeType.REFERENCES, "RUNS_ON")
        assert g.has(f"{ADF}/linkedservices/sql", SQL, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.has(f"{ADF}/triggers/nightly", pipe, EdgeType.MANAGES, "SCHEDULED_BY")
        assert g.has(ADF, "repo:https://github.com/contoso/etl", EdgeType.REFERENCES, "READS_FROM")

    def test_synapse_data_plane(self, mapped):
        g = mapped.graph
        assert g.has(
            f"{SYN}/pipelines/ingest", f"{SYN}/datasets/lake", EdgeType.REFERENCES, "READS_FROM"
        )
        assert g.has(f"{SYN}/linkedservices/adls", ST, EdgeType.REFERENCES, "DEPENDS_ON")
        assert mapped.coverage["synapse_data_plane"].status == ServiceStatus.SUCCESS

    def test_sql_replication_and_auditing(self, mapped):
        g = mapped.graph
        assert g.has(SQLDB, SQLDB_DR, EdgeType.REFERENCES, "REPLICATES_TO")
        assert g.has(SQL, SQL_DR, EdgeType.REFERENCES, "REPLICATES_TO")
        assert g.has(SQL, ST, EdgeType.LOGS_TO, "LOGS_TO")
        assert g.a(SQL).metadata["auditing_enabled"] is True

    def test_cosmos_regions_and_data_plane_roles(self, mapped):
        g = mapped.graph
        replica = f"{COSMOS}/regions/northeurope"
        assert g.a(replica).asset_type == AssetType.DYNAMODB_TABLE
        assert g.has(COSMOS, replica, EdgeType.REFERENCES, "REPLICATES_TO")
        assert g.has(
            f"entra:principal/{USER_OID}", COSMOS, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION"
        )

    def test_storage_depth(self, mapped):
        g = mapped.graph
        assert g.has(ST, ST_DR, EdgeType.REFERENCES, "REPLICATES_TO")
        user = g.a(f"{ST}/localUsers/partner")
        assert user.asset_type == AssetType.IDENTITY_USER
        assert g.has(user.arn, ST, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION")
        assert "sshAuthorizedKeys" not in user.metadata["properties"]
        st = g.a(ST)
        assert st.metadata["versioning"] is True and st.metadata["geo_replicated"] is True

    def test_kusto(self, mapped):
        g = mapped.graph
        db = f"{KUSTO}/databases/telemetry"
        assert g.has(db, f"{EH}/eventhubs/telemetry", EdgeType.REFERENCES, "READS_FROM")
        assert g.has(
            f"entra:principal/{GROUP_OID}", KUSTO, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION"
        )


class TestNetworkDepth:
    def test_dns_records(self, mapped):
        g = mapped.graph
        www = g.a(f"{ZONE}/A/www")
        assert www.asset_type == AssetType.DNS_RECORD and www.name == "www.contoso.com"
        assert g.has(ZONE, www.arn, EdgeType.CONTAINS)
        assert g.has(www.arn, PIP, EdgeType.ROUTE, "DNS_RESOLVED")
        assert g.has(f"{ZONE}/CNAME/api", APIM, EdgeType.ROUTE, "DNS_RESOLVED")
        assert g.has(f"{ZONE}/A/legacy", PIP, EdgeType.ROUTE, "DNS_RESOLVED")
        assert g.has(f"{PZONE}/A/stdata", PE, EdgeType.ROUTE, "DNS_RESOLVED")

    def test_private_resolver(self, mapped):
        g = mapped.graph
        inbound = f"{RESOLVER}/inboundEndpoints/in"
        assert g.has(SNET, inbound, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        assert g.has(RESOLVER, VNET, EdgeType.REFERENCES, "DNS_RESOLVED")
        assert g.has(f"{RULESET}/forwardingRules/corp", inbound, EdgeType.ROUTE, "DNS_RESOLVED")
        assert g.has(RULESET, VNET, EdgeType.REFERENCES, "DNS_RESOLVED")

    def test_virtual_wan(self, mapped):
        g = mapped.graph
        assert g.has(WAN, HUB, EdgeType.CONTAINS)
        conn = f"{HUB}/hubVirtualNetworkConnections/app"
        assert g.a(conn).asset_type == AssetType.PEERING_CONNECTION
        assert g.has(conn, VNET, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.has(HUB, VNET, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.has(HUB, FW, EdgeType.ROUTE, "TRANSIT_ROUTED")
        assert g.a(f"{HUB}/routingIntent/intent").metadata["inspects_internet"] is True
        assert g.has(
            f"{HUB}/hubRouteTables/defaultRouteTable", FW, EdgeType.ROUTE, "TRANSIT_ROUTED"
        )

    def test_front_door(self, mapped):
        g = mapped.graph
        route = f"{AFD_EP}/routes/default"
        assert g.a(route).asset_type == AssetType.LB_LISTENER
        assert g.has(route, AFD_OG, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert g.has(AFD_EP, AFD_OG, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
        assert g.has(
            f"{AFD_OG}/origins/web", WEB, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO"
        )
        assert g.has(f"{AFD}/secrets/cert", KV, EdgeType.REFERENCES, "CERTIFICATE_SECURES")


class TestContainersAiOps:
    def test_acr_children(self, mapped):
        g = mapped.graph
        assert g.has(ACR, f"{ACR}/replications/northeurope", EdgeType.REFERENCES, "REPLICATES_TO")
        task = f"{ACR}/tasks/build"
        assert g.a(task).asset_type == AssetType.BUILD_PROJECT
        assert g.has(
            task, "repo:https://github.com/contoso/shop", EdgeType.REFERENCES, "READS_FROM"
        )
        assert g.has(task, ACR, EdgeType.REFERENCES, "WRITES_TO")
        assert g.has(f"{ACR}/tokens/ci", ACR, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION")
        assert g.has(f"{ACR}/tokens/ci", f"{ACR}/scopeMaps/push", EdgeType.REFERENCES, "DEPENDS_ON")

    def test_openai_and_ml(self, mapped):
        g = mapped.graph
        dep = g.a(f"{OPENAI}/deployments/gpt4o")
        assert dep.asset_type == AssetType.ML_MODEL and dep.metadata["model_name"] == "gpt-4o"
        rai = f"{OPENAI}/raiPolicies/strict"
        assert g.a(rai).asset_type == AssetType.AI_GUARDRAIL
        assert g.has(rai, dep.arn, EdgeType.PROTECTS)
        assert g.a(OPENAI).metadata["model_request_logging"] is True
        assert g.has(f"{MLW}/datastores/raw", ST, EdgeType.REFERENCES, "READS_FROM")
        assert g.has(MLW, ST, EdgeType.REFERENCES, "READS_FROM")
        assert g.a(f"{MLW}/onlineEndpoints/score").is_internet_exposed
        assert g.has(
            f"{MLW}/onlineEndpoints/score",
            f"{MLW}/onlineEndpoints/score/deployments/blue",
            EdgeType.CONTAINS,
        )

    def test_search_planes(self, mapped):
        g = mapped.graph
        assert g.has(SRCH, ST, EdgeType.REFERENCES, "DEPENDS_ON")
        ds = g.a(f"{SRCH}/datasources/docs")
        assert g.has(ds.arn, ST, EdgeType.REFERENCES, "READS_FROM")
        assert "credentials" not in ds.metadata["properties"]
        indexer = f"{SRCH}/indexers/docs-indexer"
        assert g.has(indexer, ds.arn, EdgeType.REFERENCES, "READS_FROM")
        assert g.has(indexer, f"{SRCH}/indexes/docs-index", EdgeType.REFERENCES, "WRITES_TO")
        assert g.a(f"{SRCH}/indexes/docs-index").asset_type == AssetType.KNOWLEDGE_BASE
        assert g.has(f"{SRCH}/indexes/docs-index", OPENAI, EdgeType.INVOKES, "INVOKES")
        assert g.has(f"{SRCH}/skillsets/enrich", FUNC, EdgeType.INVOKES, "INVOKES")

    def test_automation(self, mapped):
        g = mapped.graph
        rb = f"{AA}/runbooks/patch"
        assert g.a(rb).asset_type == AssetType.RUNBOOK
        assert g.has(f"{AA}/schedules/nightly", rb, EdgeType.MANAGES, "SCHEDULED_BY")
        assert g.has(rb, f"{AA}/hybridRunbookWorkerGroups/workers", EdgeType.REFERENCES, "RUNS_ON")
        assert g.has(
            f"{AA}/hybridRunbookWorkerGroups/workers",
            VM,
            EdgeType.CONTAINS,
            "CLUSTER_CONTAINS_SERVICE",
        )
        assert g.has(
            f"{AA}/softwareUpdateConfigurations/monthly", VM, EdgeType.MANAGES, "SCHEDULED_BY"
        )

    def test_sentinel(self, mapped):
        g = mapped.graph
        sentinel = f"{LAW}/providers/Microsoft.SecurityInsights/onboardingStates/default"
        asset = g.a(sentinel)
        assert asset.asset_type == AssetType.THREAT_DETECTOR and asset.metadata["enabled"] is True
        asc = f"{LAW}/providers/Microsoft.SecurityInsights/dataConnectors/asc"
        aws = f"{LAW}/providers/Microsoft.SecurityInsights/dataConnectors/aws"
        assert g.has(asc, LAW, EdgeType.LOGS_TO, "LOGS_TO")
        assert g.has(asc, SUB_REF, EdgeType.MONITORS, "MONITORED_BY")
        assert any(
            r.get("relationship") == "CROSS_ACCOUNT_TRUST"
            and r["target"].startswith("arn:aws:iam::")
            for r in g.a(aws).metadata["relations"]
        )
        assert g.has(
            f"{LAW}/providers/Microsoft.SecurityInsights/automationRules/a1",
            LOGIC,
            EdgeType.INVOKES,
            "INVOKES",
        )
        assert f"cloudg:azure:sentinel:{SUB}:not-enabled" not in g.by_arn

    def test_diagnostic_settings(self, mapped):
        g = mapped.graph
        diag = f"{KV}/providers/microsoft.insights/diagnosticSettings/audit"
        assert g.has(KV, diag, EdgeType.CONTAINS)
        assert g.has(diag, LAW, EdgeType.LOGS_TO, "LOGS_TO")
        assert g.has(KV, LAW, EdgeType.LOGS_TO, "LOGS_TO")
        assert g.has(KV, f"{EH}/eventhubs/telemetry", EdgeType.LOGS_TO, "STREAMS_TO")

    def test_other_children(self, mapped):
        g = mapped.graph
        assert g.has(AMPLS, LAW, EdgeType.REFERENCES, "DEPENDS_ON")
        assert g.has(SNET, f"{BATCH}/pools/render", EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE")
        assert g.a(f"{SPRING}/apps/gateway").is_internet_exposed
        assert g.has(
            f"{DEVC}/catalogs/envs",
            "repo:https://github.com/contoso/envs",
            EdgeType.REFERENCES,
            "READS_FROM",
        )
        assert g.has(f"{DEVP}/environmentTypes/dev", SUB_REF, EdgeType.MANAGES, "OWNED_BY")
        assert g.has(APPCS, f"{APPCS}/replicas/neu", EdgeType.REFERENCES, "REPLICATES_TO")
        assert g.has(f"{BVAULT}/backupPolicies/blob", BVAULT, EdgeType.REFERENCES, "BACKUP_TO")


class TestRestCoverage:
    def test_task_records(self, mapped):
        cov = mapped.coverage
        for task in (
            "apim",
            "functions",
            "service_bus",
            "dns_records",
            "data_factory",
            "sentinel",
            "diagnostic_settings",
            "virtual_wan",
            "search_data_plane",
        ):
            assert cov[task].status == ServiceStatus.SUCCESS, (task, cov[task].error)
            assert cov[task].asset_count > 0, task
        assert cov["apim"].asset_count >= 6

    def test_forbidden_calls_are_partial(self):
        routes = _routes()
        out = collect_linked(
            {"resources": _resources()},
            routes,
            child_resources=True,
        )
        assert out.coverage["service_bus"].status == ServiceStatus.SUCCESS
        arm = FakeArm(routes, forbidden={"/topics"})
        from tests.azure_fakes import TypedFakeGraph
        from cloudg.inventory.azure_deep import AzureDeepInventoryCollector
        import asyncio

        collector = AzureDeepInventoryCollector(
            object(),
            SUB,
            graph_client_factory=lambda c: TypedFakeGraph({"resources": _resources()}),
            arm_client_factory=lambda c: arm,
            dataplane_client_factory=_dataplane,
        )
        asyncio.run(collector.collect())
        cov = {s.service: s for s in collector.coverage.services}
        assert cov["service_bus"].status == ServiceStatus.PARTIAL
        assert "403" in cov["service_bus"].error

    def test_child_resources_disabled(self):
        out = collect_linked({"resources": _resources()}, _routes(), child_resources=False)
        assert out.coverage["apim"].status == ServiceStatus.SKIPPED
        assert "child_resources" in out.coverage["apim"].error
        # only the in-cluster AKS step (its own task) still talks to ARM
        assert [c for c in out.arm.calls if c[0] != "post"] == []
        # no Sentinel data: the placeholder appears only when Sentinel was checked
        assert f"cloudg:azure:sentinel:{SUB}:not-enabled" not in {a.arn for a in out.assets}

    def test_sentinel_placeholder_when_not_onboarded(self):
        routes = {k: v for k, v in _routes().items() if "SecurityInsights" not in k}
        out = collect_linked({"resources": _resources()}, routes)
        placeholder = out.graph.a(f"cloudg:azure:sentinel:{SUB}:not-enabled")
        assert placeholder.metadata["enabled"] is False
        assert placeholder.name == "Microsoft Sentinel (not enabled)"
