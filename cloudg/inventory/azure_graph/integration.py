"""Extractors for API Management, messaging, functions, workflows and web apps.

- API Management APIs, backends (``SERVES_TRAFFIC_TO`` the Functions, App
  Service, Logic Apps or hosts behind them), products, named values
  (``READS_FROM`` Key Vault), self-hosted gateways, OAuth / OpenID
  servers, and API / service policies: ``validate-jwt`` and
  ``validate-azure-ad-token`` become ``AUTHORIZER`` assets, and
  ``set-backend-service`` routes are followed.
- Service Bus queues, topics and subscriptions (``forwardTo`` and
  dead-letter forwarding ``WRITES_TO``), Event Hubs (Capture
  ``STREAMS_TO`` storage; Kafka endpoint flag).
- Function bindings: triggers ``INVOKES / TRIGGERED_BY`` the function,
  output bindings ``WRITES_TO``, input bindings ``READS_FROM``, timer
  triggers as ``SCHEDULE`` assets (``MANAGES / SCHEDULED_BY``).
- Logic Apps actions and triggers (``INVOKES`` functions, workflows, HTTP
  hosts and API connections; recurrence ``SCHEDULED_BY``), API connections
  and the hosts they reach.
- Stream Analytics inputs (``READS_FROM``) and outputs (``WRITES_TO``).
- Event Grid subscriptions that react to Key Vault near-expiry events:
  the vault ``INVOKES / ROTATES_SECRET`` the handler.
- Web app site config (access restrictions, images, FTP / basic auth),
  source control (``READS_FROM`` the repository), Static Web Apps and their
  linked backends, Azure Monitor private link scopes.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Iterable

from cloudg.inventory._util import walk_strings
from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    _docker_image,
    _get,
    _list,
    _lower,
    _path,
    _rid,
    host_of,
    parent_resource_id,
    registry_host,
)
from cloudg.inventory.azure_graph.registry import (
    _Draft,
    _network_rule_grant,
    extractor,
    relation_row,
)
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder

_ARM_URL_PREFIX = "https://management.azure.com"
_MAX_POLICY_CHARS = 200_000


def arm_id_of(value: Any) -> str | None:
    """ARM resource ID from an ID or a ``https://management.azure.com/...`` URL."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.lower().startswith(_ARM_URL_PREFIX):
        text = text[len(_ARM_URL_PREFIX) :]
    text = text.split("?", 1)[0]
    return text if text.lower().startswith("/subscriptions/") else None


def repository_ref(b: "AzureAssetBuilder", url: Any) -> str | None:
    """Identifier of an external source repository, adding its asset once."""
    if not isinstance(url, str) or "://" not in url and not url.startswith("git@"):
        return None
    norm = url.strip().rstrip("/").removesuffix(".git").lower()
    if not norm:
        return None
    norm = re.sub(r"^https?://[^@/]+@", "https://", norm)  # never keep URL credentials
    arn = f"repo:{norm}"
    seen: set[str] = b.state.setdefault("repositories", set())
    if arn not in seen:
        seen.add(arn)
        b.add_extra(
            CloudAsset(
                arn=arn,
                name=norm.split("://", 1)[-1],
                asset_type=AssetType.SOURCE_CONNECTION,
                provider=CloudProvider.AZURE,
                region="global",
                account_id=None,
                metadata={
                    "repository_url": norm,
                    "external": True,
                    "host": host_of(norm),
                    "discovered_via": "repository-reference",
                },
            )
        )
    return arn


def _set_md_later(b: "AzureAssetBuilder", owner: str | None, values: dict[str, Any]) -> None:
    """Merge metadata into another draft at build time (it may not exist yet)."""
    if not owner:
        return
    b.state.setdefault("late_md", {}).setdefault(owner.lower(), {}).update(
        {k: v for k, v in values.items() if v not in (None, "", [], {})}
    )
    b.at_build(_apply_late_md)


def _apply_late_md(b: "AzureAssetBuilder") -> None:
    for owner, values in (b.state.get("late_md") or {}).items():
        d = b.draft(owner)
        if d is not None:
            d.md.update(values)


# ── API Management ──

_JWT_RE = re.compile(r"<validate-(jwt|azure-ad-token)\b(.*?)(?:/>|</validate-\1>)", re.S | re.I)
_ATTR_RE = re.compile(r'([a-zA-Z-]+)\s*=\s*"([^"]*)"')
_BACKEND_RE = re.compile(r"<set-backend-service\b([^>]*)>", re.I)
_SEND_RE = re.compile(r"<send-request\b.*?<set-url>\s*([^<\s]+)\s*</set-url>", re.S | re.I)
_URL_RE = re.compile(r'url="([^"]+)"', re.I)


def _attrs(text: str) -> dict[str, str]:
    return {k.lower(): v for k, v in _ATTR_RE.findall(text)}


def _api_hosts(d: _Draft, b: "AzureAssetBuilder", url: Any) -> None:
    host = host_of(url)
    d.add(
        rel(host, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO", description="API backend URL")
    )


@extractor("microsoft.apimanagement/service/apis")
def _x_apim_api(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    service = parent_resource_id(d.id)
    d.name = _get(p, "displayName") or d.name
    d.md.update(
        {
            "api_type": _get(p, "type") or _get(p, "apiType"),
            "path": _get(p, "path"),
            "protocols": _list(_get(p, "protocols")),
            "service_url": _get(p, "serviceUrl"),
            "subscription_required": _get(p, "subscriptionRequired"),
            "revision": _get(p, "apiRevision"),
            "is_current": _get(p, "isCurrent"),
            "service_id": service,
        }
    )
    _api_hosts(d, b, _get(p, "serviceUrl"))
    parent = b.draft(service)
    if parent is not None and parent.exposed:
        d.exposed = True


def _policy_relations(
    b: "AzureAssetBuilder", owner: str, service: str | None, xml: str
) -> dict[str, Any]:
    """Relations / metadata of one APIM policy document (never stored itself)."""
    xml = xml[:_MAX_POLICY_CHARS]
    md: dict[str, Any] = {}
    jwt = []
    for kind, body in _JWT_RE.findall(xml):
        attrs = _attrs(body.split(">", 1)[0])
        idps = [host_of(u) for u in _URL_RE.findall(body)]
        jwt.append(
            {
                "kind": f"validate-{kind.lower()}",
                "header": attrs.get("header-name"),
                "tenant_id": attrs.get("tenant-id"),
                "openid_hosts": [h for h in dict.fromkeys(idps) if h],
            }
        )
    if jwt:
        md["jwt_validation"] = jwt
        b.add_row(
            {
                "id": f"{owner}/authorizers/jwt",
                "name": "JWT validation",
                "type": "microsoft.apimanagement/service/apis/authorizers",
                "subscriptionId": b.subscription_id,
                "properties": {"validations": jwt},
            },
            synthetic=True,
        )
        b.defer(
            owner,
            rel(
                f"{owner}/authorizers/jwt",
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="authorizer",
            ),
        )
    for match in _BACKEND_RE.findall(xml):
        attrs = _attrs(match)
        backend = attrs.get("backend-id")
        if backend and service and "@" not in backend and "{" not in backend:
            b.defer(
                owner,
                rel(
                    f"{service}/backends/{backend}",
                    EdgeType.LOAD_BALANCER_TARGET,
                    "SERVES_TRAFFIC_TO",
                    description="set-backend-service",
                ),
            )
        base = attrs.get("base-url")
        if base and "{" not in base and "@" not in base:
            b.defer(owner, rel(host_of(base), EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO"))
    for url in _SEND_RE.findall(xml):
        if "{" not in url and "@" not in url:
            b.defer(
                owner, rel(host_of(url), EdgeType.INVOKES, "INVOKES", description="send-request")
            )
    lowered = xml.lower()
    md["ip_filter"] = "<ip-filter" in lowered or None
    md["rate_limited"] = "<rate-limit" in lowered or "<quota" in lowered or None
    md["managed_identity_auth"] = "<authentication-managed-identity" in lowered or None
    return md


@relation_row(
    "microsoft.apimanagement/service/apis/policies", "microsoft.apimanagement/service/policies"
)
def _apim_policy(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    xml = _get(row.get("properties") or {}, "value")
    owner = parent_resource_id(row.get("id"))
    if not isinstance(xml, str) or not owner:
        return
    # service-level policy: the owner is the service; API policy: the API's parent
    service_level = str(row.get("type", "")).lower().endswith("/service/policies")
    service = owner if service_level else parent_resource_id(owner)
    _set_md_later(b, owner, _policy_relations(b, owner, service, xml))


@extractor("microsoft.apimanagement/service/apis/authorizers")
def _x_apim_authorizer(d: _Draft, b: "AzureAssetBuilder") -> None:
    validations = _get(d.props, "validations") or []
    d.md["validations"] = validations
    for v in validations:
        for host in v.get("openid_hosts") or []:
            d.add(rel(host, EdgeType.REFERENCES, "DEPENDS_ON", description="OpenID configuration"))


@extractor("microsoft.apimanagement/service/backends")
def _x_apim_backend(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    target = arm_id_of(_get(p, "resourceId"))
    d.md.update(
        {
            "url": _get(p, "url"),
            "protocol": _get(p, "protocol"),
            "backend_type": _get(p, "type"),
            "resource_id": target,
            "validate_certificate_chain": _path(p, "tls", "validateCertificateChain"),
            "circuit_breaker": bool(_get(p, "circuitBreaker")),
        }
    )
    d.add(
        rel(
            target,
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
            description="backend resource",
        )
    )
    if not target:
        _api_hosts(d, b, _get(p, "url"))
    for member in _list(_path(p, "pool", "services")):
        d.add(
            rel(
                _rid(member),
                EdgeType.LOAD_BALANCER_TARGET,
                "SERVES_TRAFFIC_TO",
                description="pool member",
            )
        )
    # credentials are header / query names only; never keep their values
    d.props = {k: v for k, v in p.items() if _lower(k) != "credentials"}


@extractor("microsoft.apimanagement/service/products")
def _x_apim_product(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.name = _get(p, "displayName") or d.name
    d.md.update(
        {
            "state": _get(p, "state"),
            "subscription_required": _get(p, "subscriptionRequired"),
            "approval_required": _get(p, "approvalRequired"),
        }
    )


@relation_row("microsoft.apimanagement/service/products/apis")
def _apim_product_api(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    product = parent_resource_id(row.get("id"))
    service = parent_resource_id(product)
    name = row.get("name") or str(row.get("id", "")).rsplit("/", 1)[-1]
    if product and service:
        b.defer(product, rel(f"{service}/apis/{name}", EdgeType.REFERENCES, "DEPENDS_ON"))


@extractor("microsoft.apimanagement/service/namedvalues")
def _x_apim_named_value(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    secret_id = _path(p, "keyVault", "secretIdentifier")
    d.md.update(
        {
            "secret": _get(p, "secret"),
            "key_vault_secret": secret_id,
            "display_name": _get(p, "displayName"),
        }
    )
    d.add(
        rel(host_of(secret_id), EdgeType.REFERENCES, "READS_FROM", description="Key Vault secret")
    )
    d.props = {k: v for k, v in p.items() if _lower(k) != "value"}


@extractor("microsoft.apimanagement/service/gateways")
def _x_apim_gateway(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["self_hosted"] = True
    d.md["location"] = _path(d.props, "locationData", "name")


@extractor(
    "microsoft.apimanagement/service/authorizationservers",
    "microsoft.apimanagement/service/openidconnectproviders",
)
def _x_apim_idp(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for key in ("authorizationEndpoint", "tokenEndpoint", "metadataEndpoint"):
        d.add(rel(host_of(_get(p, key)), EdgeType.REFERENCES, "DEPENDS_ON", description=key))
    d.props = {k: v for k, v in p.items() if "secret" not in k.lower()}


# ── Service Bus, Event Hubs ──


def _namespace_host(entity_id: str) -> tuple[str | None, str | None]:
    """(namespace name, namespace host) of a Service Bus / Event Hubs entity."""
    ns = parent_resource_id(entity_id)
    if ns and "/topics/" in ns.lower():
        ns = parent_resource_id(ns)
    name = ns.rsplit("/", 1)[-1].lower() if ns else None
    return name, f"{name}.servicebus.windows.net" if name else None


def _entity_aliases(d: _Draft, kind: str) -> None:
    ns, host = _namespace_host(d.id)
    if host:
        d.alias(f"{host}/{d.name.lower()}", f"servicebus:{ns}/{d.name.lower()}")
    d.alias(f"{kind}:{d.name.lower()}")


def _forward(d: _Draft, key: str, description: str) -> None:
    target = _get(d.props, key)
    if not isinstance(target, str) or not target:
        return
    ns, host = _namespace_host(d.id)
    ref = target.lower() if "://" not in target else host_of(target)
    if ns and "/" not in str(ref) and "." not in str(ref):
        ref = f"servicebus:{ns}/{ref}"
    d.add(rel(ref, EdgeType.REFERENCES, "WRITES_TO", description=description))


@extractor("microsoft.servicebus/namespaces/queues", "microsoft.servicebus/namespaces/topics")
def _x_servicebus_entity(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    queue = d.type.endswith("/queues")
    _entity_aliases(d, "servicebus-queue" if queue else "servicebus-topic")
    d.md.update(
        {
            "status": _get(p, "status"),
            "requires_session": _get(p, "requiresSession"),
            "max_delivery_count": _get(p, "maxDeliveryCount"),
            "dead_lettering_on_expiration": _get(p, "deadLetteringOnMessageExpiration"),
            "partitioned": _get(p, "enablePartitioning"),
            "message_count": _get(p, "messageCount"),
            "subscription_count": _get(p, "subscriptionCount"),
        }
    )
    _forward(d, "forwardTo", "auto-forward")
    _forward(d, "forwardDeadLetteredMessagesTo", "dead-letter forward")


@extractor("microsoft.servicebus/namespaces/topics/subscriptions")
def _x_servicebus_subscription(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md.update(
        {
            "status": _get(p, "status"),
            "max_delivery_count": _get(p, "maxDeliveryCount"),
            "requires_session": _get(p, "requiresSession"),
        }
    )
    _forward(d, "forwardTo", "auto-forward")
    _forward(d, "forwardDeadLetteredMessagesTo", "dead-letter forward")


@extractor("microsoft.eventhub/namespaces/eventhubs")
def _x_event_hub(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    _entity_aliases(d, "eventhub")
    capture = _get(p, "captureDescription") or {}
    dest = _path(capture, "destination", "properties") or {}
    d.md.update(
        {
            "partition_count": _get(p, "partitionCount"),
            "retention_days": _get(p, "messageRetentionInDays")
            or _path(p, "retentionDescription", "retentionTimeInHours"),
            "status": _get(p, "status"),
            "capture_enabled": _get(capture, "enabled"),
        }
    )
    if _get(capture, "enabled"):
        storage = _get(dest, "storageAccountResourceId")
        lake = _get(dest, "dataLakeAccountName")
        d.add(
            rel(
                storage or (f"{str(lake).lower()}.dfs.core.windows.net" if lake else None),
                EdgeType.LOGS_TO,
                "STREAMS_TO",
                description="Event Hubs Capture",
                container=_get(dest, "blobContainer"),
            )
        )


@extractor("microsoft.eventhub/namespaces")
def _x_event_hub_namespace_kafka(d: _Draft, b: "AzureAssetBuilder") -> None:
    kafka = _get(d.props, "kafkaEnabled")
    d.md["kafka_enabled"] = kafka
    if kafka:
        d.md["message_broker_protocol"] = "kafka"
        d.alias(f"{d.name.lower()}.servicebus.windows.net:9093")


# ── Functions ──

_TRIGGER_TARGETS = {
    "servicebustrigger": ("servicebus", "queueName", "topicName"),
    "servicebus": ("servicebus", "queueName", "topicName"),
    "eventhubtrigger": ("eventhub", "eventHubName", None),
    "eventhub": ("eventhub", "eventHubName", None),
}


def _binding_target(binding: dict[str, Any]) -> str | None:
    kind = _lower(_get(binding, "type"))
    spec = _TRIGGER_TARGETS.get(kind)
    if spec is None:
        return None
    family, first, second = spec
    if family == "servicebus":
        queue = _get(binding, first)
        if queue:
            return f"servicebus-queue:{str(queue).lower()}"
        topic = _get(binding, second) if second else None
        return f"servicebus-topic:{str(topic).lower()}" if topic else None
    hub = _get(binding, first)
    return f"eventhub:{str(hub).lower()}" if hub and "%" not in str(hub) else None


@extractor("microsoft.web/sites/functions")
def _x_function(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    bindings = [x for x in _list(_path(p, "config", "bindings")) if isinstance(x, dict)]
    triggers = [x for x in bindings if _lower(_get(x, "type")).endswith("trigger")]
    d.md.update(
        {
            "function_name": d.name.rsplit("/", 1)[-1],
            "language": _get(p, "language"),
            "disabled": _get(p, "isDisabled"),
            "invoke_url": _get(p, "invoke_url_template"),
            "triggers": [_get(t, "type") for t in triggers],
            "bindings": [
                {
                    "type": _get(x, "type"),
                    "direction": _get(x, "direction"),
                    "name": _get(x, "name"),
                }
                for x in bindings
            ],
        }
    )
    d.alias(host_of(_get(p, "invoke_url_template")))
    for binding in bindings:
        kind = _lower(_get(binding, "type"))
        direction = _lower(_get(binding, "direction"))
        target = _binding_target(binding)
        if kind == "httptrigger":
            d.md["http_auth_level"] = _get(binding, "authLevel")
            if _lower(_get(binding, "authLevel")) == "anonymous":
                d.md["anonymous_http"] = True
        elif kind == "timertrigger":
            _timer(d, b, binding)
        elif kind.endswith("trigger"):
            d.add(
                rel(target, EdgeType.INVOKES, "TRIGGERED_BY", reverse=True, description=f"{kind}")
            )
        elif direction == "out":
            d.add(rel(target, EdgeType.REFERENCES, "WRITES_TO", description=f"{kind} output"))
        elif direction == "in":
            d.add(rel(target, EdgeType.REFERENCES, "READS_FROM", description=f"{kind} input"))


def _timer(d: _Draft, b: "AzureAssetBuilder", binding: dict[str, Any]) -> None:
    schedule = _get(binding, "schedule")
    b.add_row(
        {
            "id": f"{d.id}/timers/{_get(binding, 'name') or 'timer'}",
            "name": f"timer {schedule}",
            "type": "microsoft.web/sites/functions/timers",
            "location": d.region,
            "subscriptionId": d.account_id,
            "properties": {"schedule": schedule, "runOnStartup": _get(binding, "runOnStartup")},
        },
        synthetic=True,
    )


@extractor("microsoft.web/sites/functions/timers", "microsoft.logic/workflows/triggers")
def _x_schedule(d: _Draft, b: "AzureAssetBuilder") -> None:
    target = parent_resource_id(d.id)
    d.md["schedule"] = _get(d.props, "schedule") or _get(d.props, "recurrence")
    d.add(rel(target, EdgeType.MANAGES, "SCHEDULED_BY", description="schedule"))


# ── Logic Apps, API connections ──

_CONN_KEY_RE = re.compile(r"\$connections'[\])]*\['([^']+)'\]")


def _walk_actions(actions: Any) -> Iterable[tuple[str, dict[str, Any]]]:
    stack = [actions]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        for name, action in current.items():
            if not isinstance(action, dict):
                continue
            yield name, action
            stack.append(_get(action, "actions"))
            stack.append(_path(action, "else", "actions"))
            stack.append(_path(action, "default", "actions"))
            for case in (_get(action, "cases") or {}).values():
                stack.append(_get(case, "actions"))


def _connection_id(item: dict[str, Any], connections: dict[str, Any]) -> str | None:
    ref = _path(item, "inputs", "host", "connection", "name")
    m = _CONN_KEY_RE.search(str(ref or ""))
    if not m:
        return None
    return _get(_get(connections, m.group(1)) or {}, "connectionId")


def _logic_action_target(item: dict[str, Any], connections: dict[str, Any]) -> str | None:
    kind = _lower(_get(item, "type"))
    inputs = _get(item, "inputs") or {}
    if kind in ("apiconnection", "apiconnectionwebhook"):
        return _connection_id(item, connections)
    if kind == "http":
        uri = _get(inputs, "uri")
        return host_of(uri) if isinstance(uri, str) and "@" not in uri else None
    if kind == "function":
        return _path(inputs, "function", "id")
    if kind == "workflow":
        return _path(inputs, "host", "workflow", "id")
    return None


@extractor("microsoft.logic/workflows")
def _x_logic_app(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    definition = _get(p, "definition") or {}
    connections = _path(p, "parameters", "$connections", "value") or {}
    triggers = _get(definition, "triggers") or {}
    action_count = 0
    for _name, action in _walk_actions(_get(definition, "actions")):
        action_count += 1
        d.add(
            rel(
                _logic_action_target(action, connections),
                EdgeType.INVOKES,
                "INVOKES",
                description=f"{_get(action, 'type')} action",
            )
        )
    trigger_kinds = []
    for name, trigger in triggers.items() if isinstance(triggers, dict) else []:
        kind = _lower(_get(trigger, "type"))
        trigger_kinds.append(kind)
        if kind == "recurrence":
            b.add_row(
                {
                    "id": f"{d.id}/triggers/{name}",
                    "name": f"{name} ({_path(trigger, 'recurrence', 'frequency')})",
                    "type": "microsoft.logic/workflows/triggers",
                    "location": d.region,
                    "subscriptionId": d.account_id,
                    "properties": {"recurrence": _get(trigger, "recurrence")},
                },
                synthetic=True,
            )
        elif kind == "request":
            d.md["http_trigger"] = True
        else:
            source = _connection_id(trigger, connections)
            d.add(
                rel(
                    source,
                    EdgeType.INVOKES,
                    "TRIGGERED_BY",
                    reverse=True,
                    description=f"{kind} trigger",
                )
            )
    for conn in connections.values() if isinstance(connections, dict) else []:
        d.add(
            rel(
                _get(conn, "connectionId"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="API connection",
            )
        )
    d.md.update(
        {
            "state": _get(p, "state"),
            "trigger_types": trigger_kinds,
            "action_count": action_count,
            "allowed_caller_ips": [
                _get(r, "addressRange")
                for r in _list(_path(p, "accessControl", "triggers", "allowedCallerIpAddresses"))
            ],
        }
    )
    d.add(rel(_rid(_get(p, "integrationAccount")), EdgeType.REFERENCES, "DEPENDS_ON"))


@extractor("microsoft.web/connections")
def _x_api_connection(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    api = _path(p, "api", "id") or ""
    d.md.update(
        {
            "api": str(api).rsplit("/", 1)[-1] or _path(p, "api", "name"),
            "status": [_get(s, "status") for s in _list(_get(p, "statuses"))],
            "display_name": _get(p, "displayName"),
        }
    )
    hosts = []
    for text in walk_strings(_get(p, "parameterValues") or {}):
        host = host_of(text) if "://" in text else None
        if host and host not in hosts:
            hosts.append(host)
    for host in hosts[:10]:
        d.add(rel(host, EdgeType.REFERENCES, "DEPENDS_ON", description="connection endpoint"))
    # parameter values and the signed-in user are not inventory
    d.props = {
        k: v
        for k, v in p.items()
        if _lower(k) not in ("parametervalues", "parametervalueset", "authenticateduser")
    }


# ── Stream Analytics ──


def _stream_target(props: dict[str, Any]) -> str | None:
    ds = _get(props, "datasource") or {}
    kind = _lower(_get(ds, "type"))
    dp = _get(ds, "properties") or {}
    ns = _lower(_get(dp, "serviceBusNamespace"))
    if kind == "microsoft.servicebus/eventhub" or kind == "microsoft.eventhub/eventhub":
        return f"{ns}.servicebus.windows.net/{_lower(_get(dp, 'eventHubName'))}" if ns else None
    if kind == "microsoft.servicebus/queue":
        return f"{ns}.servicebus.windows.net/{_lower(_get(dp, 'queueName'))}" if ns else None
    if kind == "microsoft.servicebus/topic":
        return f"{ns}.servicebus.windows.net/{_lower(_get(dp, 'topicName'))}" if ns else None
    if kind in ("microsoft.storage/blob", "microsoft.storage/table", "microsoft.storage/datalake"):
        accounts = _list(_get(dp, "storageAccounts")) or [{"accountName": _get(dp, "accountName")}]
        name = _lower(_get(accounts[0], "accountName")) if accounts else ""
        suffix = {"microsoft.storage/table": "table", "microsoft.storage/datalake": "dfs"}.get(
            kind, "blob"
        )
        return f"{name}.{suffix}.core.windows.net" if name else None
    if kind == "microsoft.devices/iothubs":
        name = _lower(_get(dp, "iotHubNamespace"))
        return f"{name}.azure-devices.net" if name else None
    if kind.startswith("microsoft.sql/server"):
        server = _lower(_get(dp, "server"))
        return server if "." in server else (f"{server}.database.windows.net" if server else None)
    if kind == "microsoft.storage/documentdb":
        acct = _lower(_get(dp, "accountId"))
        return f"{acct}.documents.azure.com" if acct else None
    if kind == "microsoft.azurefunction":
        app = _lower(_get(dp, "functionAppName"))
        return f"{app}.azurewebsites.net" if app else None
    return host_of(_get(dp, "url") or _get(dp, "endpoint"))


@relation_row(
    "microsoft.streamanalytics/streamingjobs/inputs",
    "microsoft.streamanalytics/streamingjobs/outputs",
)
def _stream_io(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    job = parent_resource_id(row.get("id"))
    props = row.get("properties") or {}
    target = _stream_target(props)
    output = str(row.get("type", "")).lower().endswith("/outputs")
    b.defer(
        job,
        rel(
            target,
            EdgeType.REFERENCES,
            "WRITES_TO" if output else "READS_FROM",
            description=f"{'output' if output else 'input'} {row.get('name')}",
            datasource=_path(props, "datasource", "type"),
        ),
    )


@extractor("microsoft.streamanalytics/streamingjobs")
def _x_stream_job(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.md["job_type"] = _get(p, "jobType")
    d.md["state"] = _get(p, "jobState")
    d.add(rel(_path(p, "cluster", "id"), EdgeType.CONTAINS, reverse=True, description="cluster"))
    for io in _list(_get(p, "inputs")) + _list(_get(p, "outputs")):
        if isinstance(io, dict) and io.get("id"):
            _stream_io(io, b)


# ── Event Grid: Key Vault rotation handlers ──

_ROTATION_EVENTS = (
    "microsoft.keyvault.secretnearexpiry",
    "microsoft.keyvault.secretexpired",
    "microsoft.keyvault.certificatenearexpiry",
    "microsoft.keyvault.keynearexpiry",
)


def _subscription_target(p: dict[str, Any]) -> str | None:
    dest = _get(p, "destination") or {}
    return _path(dest, "properties", "resourceId") or host_of(
        _path(dest, "properties", "endpointUrl")
    )


def _rotation_handlers(b: "AzureAssetBuilder") -> None:
    for sub_id, target in b.state.get("rotation_subscriptions", []):
        topic = parent_resource_id(sub_id)
        topic_draft = b.draft(topic)
        source = _get(topic_draft.props, "source") if topic_draft is not None else topic
        if isinstance(source, str) and "/microsoft.keyvault/vaults/" in source.lower():
            b.defer(
                source,
                rel(
                    target,
                    EdgeType.INVOKES,
                    "ROTATES_SECRET",
                    description="near-expiry event handler",
                    event_subscription=sub_id,
                ),
            )


@extractor(
    "microsoft.eventgrid/systemtopics/eventsubscriptions",
    "microsoft.eventgrid/eventsubscriptions",
)
def _x_rotation_subscription(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    events = [str(e).lower() for e in _list(_path(p, "filter", "includedEventTypes"))]
    target = _subscription_target(p)
    if d.type == "microsoft.eventgrid/eventsubscriptions":  # extension subscription on a resource
        d.md["included_event_types"] = events
        d.add(rel(target, EdgeType.INVOKES, "INVOKES", description="event delivery"))
        source = parent_resource_id(d.id)
        if source and target:
            b.defer(
                source, rel(target, EdgeType.INVOKES, "INVOKES", description=f"events {d.name}")
            )
    if target and any(e in _ROTATION_EVENTS for e in events):
        b.state.setdefault("rotation_subscriptions", []).append((d.id, target))
        b.at_build(_rotation_handlers)


# ── Web apps, Static Web Apps, Monitor private link scopes ──


@relation_row("microsoft.web/sites/config", "microsoft.web/sites/slots/config")
def _site_config(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    site = parent_resource_id(row.get("id"))
    p = row.get("properties") or {}
    if not site or not str(row.get("name", "")).lower().endswith("web"):
        return
    images = [
        i for i in (_docker_image(_get(p, k)) for k in ("linuxFxVersion", "windowsFxVersion")) if i
    ]
    for image in images:
        b.defer(site, rel(registry_host(image), EdgeType.USES_IMAGE, "RUNS_ON", image=image))
    rules = []
    for key in ("ipSecurityRestrictions", "scmIpSecurityRestrictions"):
        for r in _list(_get(p, key)):
            subnet = _get(r, "vnetSubnetResourceId")
            rules.append(
                {
                    "scm": key.startswith("scm"),
                    "action": _get(r, "action"),
                    "ip": _get(r, "ipAddress"),
                    "subnet": subnet,
                    "service_tag": _get(r, "tag"),
                }
            )
            if subnet and _lower(_get(r, "action")) == "allow":
                b.defer(site, _network_rule_grant(subnet, "access restriction"))
    _set_md_later(
        b,
        site,
        {
            "access_restrictions": rules,
            "ftps_state": _get(p, "ftpsState"),
            "min_tls_version": _get(p, "minTlsVersion"),
            "remote_debugging": _get(p, "remoteDebuggingEnabled"),
            "vnet_route_all": _get(p, "vnetRouteAllEnabled"),
            "acr_managed_identity": _get(p, "acrUseManagedIdentityCreds"),
            "http20": _get(p, "http20Enabled"),
        },
    )


@relation_row("microsoft.web/sites/sourcecontrols", "microsoft.web/sites/slots/sourcecontrols")
def _site_source_control(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    site = parent_resource_id(row.get("id"))
    p = row.get("properties") or {}
    repo = repository_ref(b, _get(p, "repoUrl"))
    b.defer(
        site,
        rel(
            repo,
            EdgeType.REFERENCES,
            "READS_FROM",
            description="deployment source",
            branch=_get(p, "branch"),
            github_action=_get(p, "isGitHubAction"),
        ),
    )


@relation_row("microsoft.web/sites/basicpublishingcredentialspolicies")
def _site_basic_auth(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    site = parent_resource_id(row.get("id"))
    kind = str(row.get("name") or "").lower()
    _set_md_later(b, site, {f"basic_auth_{kind}": _get(row.get("properties") or {}, "allow")})


@extractor("microsoft.web/staticsites")
def _x_static_site(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.exposed = True
    host = _get(p, "defaultHostname")
    d.alias(host.lower() if isinstance(host, str) else None)
    for domain in _list(_get(p, "customDomains")):
        d.alias(str(domain).lower())
    d.md.update(
        {
            "default_host_name": host,
            "repository_url": _get(p, "repositoryUrl"),
            "branch": _get(p, "branch"),
            "staging_policy": _get(p, "stagingEnvironmentPolicy"),
        }
    )
    d.add(rel(repository_ref(b, _get(p, "repositoryUrl")), EdgeType.REFERENCES, "READS_FROM"))
    for backend in _list(_get(p, "linkedBackends")):
        d.add(
            rel(
                _get(backend, "backendResourceId"),
                EdgeType.LOAD_BALANCER_TARGET,
                "SERVES_TRAFFIC_TO",
            )
        )


@relation_row(
    "microsoft.web/staticsites/linkedbackends",
    "microsoft.web/staticsites/userprovidedfunctionapps",
)
def _static_site_backend(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    p = row.get("properties") or {}
    target = _get(p, "backendResourceId") or _get(p, "functionAppResourceId")
    b.defer(
        parent_resource_id(row.get("id")),
        rel(
            target, EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO", description="linked backend"
        ),
    )


@extractor("microsoft.insights/privatelinkscopes")
def _x_monitor_pls(d: _Draft, b: "AzureAssetBuilder") -> None:
    settings = _get(d.props, "accessModeSettings") or {}
    d.md["ingestion_access_mode"] = _get(settings, "ingestionAccessMode")
    d.md["query_access_mode"] = _get(settings, "queryAccessMode")


@relation_row("microsoft.insights/privatelinkscopes/scopedresources")
def _monitor_scoped_resource(row: dict[str, Any], b: "AzureAssetBuilder") -> None:
    linked = _get(row.get("properties") or {}, "linkedResourceId")
    b.defer(
        parent_resource_id(row.get("id")),
        rel(linked, EdgeType.REFERENCES, "DEPENDS_ON", description="scoped resource"),
    )


__all__ = ["arm_id_of", "repository_ref"]
