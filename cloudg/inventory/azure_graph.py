"""Azure Resource Graph collection and relation extraction.

Azure Resource Graph (ARG) returns every resource of a subscription with
its full ``properties`` bag in a handful of paginated KQL queries, which is
both far faster and far richer than enumerating each service SDK. This
module holds the provider-neutral half of the Azure inventory:

- :func:`run_query` — paginated ARG queries (``skipToken``) with 429
  back-off, against any client exposing ``resources(request)``.
- :class:`AzureAssetBuilder` — turns ARM-shaped rows (from ARG *or* from
  SDK models serialised with :func:`to_rest`) into :class:`CloudAsset`
  objects carrying typed ``metadata["relations"]`` and
  ``metadata["aliases"]`` for the
  :class:`~cloudg.inventory.linker.RelationshipLinker`.
- An extractor registry keyed by lowercase ARM resource type. Every row
  goes through the common extractors (identity, managedBy, parent /
  resource-group containment, private endpoint connections, PaaS
  exposure) and then the type-specific ones.

Identifier conventions:

- Entra principals (users, groups, service principals, managed
  identities): ``entra:principal/<objectId>`` (lowercase).
- Log Analytics workspaces are also reachable as
  ``loganalytics:<customerId>``.
- Hostnames (``x.azurecr.io``, ``x.vault.azure.net``, web app default
  host names, storage endpoints, ...) are registered as lowercase aliases.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from types import SimpleNamespace
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlparse

from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.inventory.aws_services._base import rel
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

PRINCIPAL_PREFIX = "entra:principal/"
LOG_ANALYTICS_PREFIX = "loganalytics:"
ACR_PULL_ROLE_ID = "7f951dda-4ed3-4680-a7ca-43fe172d538d"

# Built-in role definition GUIDs -> names (used when ARG cannot join names)
BUILTIN_ROLES: dict[str, str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f6fb9d41c8d7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    ACR_PULL_ROLE_ID: "AcrPull",
    "8311e382-0749-4cb8-b61a-304f252e45ec": "AcrPush",
}

PRIVILEGED_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "key vault administrator",
    "virtual machine contributor",
    "storage account contributor",
    "azure kubernetes service cluster admin role",
    "azure kubernetes service rbac cluster admin",
}

# Maps lowercase ARM resource types to normalised AssetTypes.
# ARM type -> AssetType; the table lives in catalogs/azure_arm_types.yaml.
_ARM_TYPE_MAP: dict[str, AssetType] = asset_type_map(
    load_catalog("azure_arm_types").get("arm_types"), "azure_arm_types"
)


def asset_type_from_arm(resource_type: str | None, kind: str | None = None) -> AssetType:
    """Best-effort AssetType classification from an ARM resource type.

    Args:
        resource_type: ARM type, e.g. ``Microsoft.Web/sites`` (any case).
        kind: The resource ``kind``; distinguishes function apps from web apps.
    """
    if not resource_type:
        return AssetType.OTHER
    rtype = resource_type.lower()
    if (
        rtype in ("microsoft.web/sites", "microsoft.web/sites/slots")
        and kind
        and "functionapp" in kind.lower()
    ):
        return AssetType.CLOUD_FUNCTION
    return _ARM_TYPE_MAP.get(rtype, AssetType.OTHER)


# ---------------------------------------------------------------------------
# Identifier helpers
# ---------------------------------------------------------------------------

_RG_RE = re.compile(r"^(/subscriptions/[^/]+/resourceGroups/[^/]+)", re.IGNORECASE)
_SUB_RE = re.compile(r"^/subscriptions/([^/]+)", re.IGNORECASE)
_MG_RE = re.compile(r"^/providers/Microsoft\.Management/managementGroups/([^/]+)", re.IGNORECASE)
_GUID_TAIL_RE = re.compile(
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/?$"
)


def principal_ref(principal_id: Any) -> str | None:
    """Canonical identifier for an Entra principal object ID."""
    if not principal_id or not isinstance(principal_id, str):
        return None
    return f"{PRINCIPAL_PREFIX}{principal_id.strip().lower()}"


def subscription_ref(subscription_id: str) -> str:
    return f"/subscriptions/{subscription_id}"


def management_group_ref(name: str) -> str:
    return f"/providers/Microsoft.Management/managementGroups/{name}"


def normalize_scope(scope: Any) -> str | None:
    """Canonical form of an RBAC / policy scope (management groups rebuilt)."""
    if not isinstance(scope, str) or not scope:
        return None
    m = _MG_RE.match(scope)
    if m and scope.rstrip("/").count("/") == 4:
        return management_group_ref(m.group(1))
    if scope.strip() == "/":
        return "/"
    return scope.rstrip("/")


def subscription_of(resource_id: str | None) -> str | None:
    m = _SUB_RE.match(resource_id or "")
    return m.group(1) if m else None


def resource_group_of(resource_id: str | None) -> str | None:
    """``/subscriptions/<s>/resourceGroups/<rg>`` of a resource ID."""
    m = _RG_RE.match(resource_id or "")
    return m.group(1) if m else None


def _segments(resource_id: str) -> tuple[list[str], int]:
    parts = resource_id.split("/")
    lower = [p.lower() for p in parts]
    idx = -1
    for i in range(len(lower) - 1, -1, -1):
        if lower[i] == "providers":
            idx = i
            break
    return parts, idx


def parent_resource_id(resource_id: str | None) -> str | None:
    """Immediate parent of a nested (``/t1/n1/t2/n2``) or extension resource."""
    if not resource_id:
        return None
    parts, idx = _segments(resource_id.rstrip("/"))
    if idx < 0:
        return None
    tail = parts[idx + 2 :]  # after the namespace: type/name pairs
    if len(tail) >= 4 and len(tail) % 2 == 0:
        return "/".join(parts[: len(parts) - 2])
    if len(tail) == 2:
        prefix = parts[:idx]
        if any(p.lower() == "providers" for p in prefix):
            return "/".join(prefix)  # extension resource on another resource
    return None


def owner_resource_id(sub_resource_id: str | None) -> str | None:
    """Top-level resource owning a sub-resource (ipConfiguration, pool, ...)."""
    if not sub_resource_id or not isinstance(sub_resource_id, str):
        return None
    parts, idx = _segments(sub_resource_id)
    if idx < 0 or idx + 3 >= len(parts):
        return sub_resource_id
    return "/".join(parts[: idx + 4])


def host_of(url: Any) -> str | None:
    """Lowercase hostname of a URL or bare host."""
    if not isinstance(url, str) or not url.strip():
        return None
    value = url.strip()
    if "://" not in value:
        value = "https://" + value
    try:
        host = urlparse(value).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def registry_host(image: Any) -> str | None:
    """Registry host of a container image reference (None for Docker Hub)."""
    if not isinstance(image, str) or "/" not in image:
        return None
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first.lower()
    return None


def _docker_image(fx_version: Any) -> str | None:
    if isinstance(fx_version, str) and fx_version.upper().startswith("DOCKER|"):
        return fx_version.split("|", 1)[1].strip() or None
    return None


def _kql(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._\-]", "", value or "")


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------


def to_rest(obj: Any, depth: int = 0) -> Any:
    """Serialise an Azure SDK model (TypeSpec or msrest) to its REST JSON shape."""
    if depth > 40:
        return None
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, str):
        return str(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return None
    serialize = getattr(obj, "serialize", None)
    if callable(serialize) and not isinstance(obj, Mapping) and hasattr(obj, "_attribute_map"):
        try:
            return to_rest(serialize(keep_readonly=True), depth + 1)
        except Exception:  # pragma: no cover - defensive
            return None
    if isinstance(obj, Mapping):
        return {str(k): to_rest(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_rest(v, depth + 1) for v in obj]
    return str(obj)


_REDACT_KEYS = {
    "customdata",
    "userdata",
    "password",
    "adminpassword",
    "administratorloginpassword",
    "secret",
    "secretvalue",
    "securevalue",
    "connectionstring",
    "connectionstrings",
    "primarykey",
    "secondarykey",
    "accesskey",
    "accesskeys",
    "sastoken",
    "definition",
    "protectedsettings",
}
_MAX_STR = 4096
_MAX_LIST = 500


def sanitize(value: Any, depth: int = 0) -> Any:
    """Copy of a properties bag with secrets redacted and sizes bounded."""
    if depth > 16:
        return None
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            kl = key.lower()
            if kl in _REDACT_KEYS:
                out[key] = "<redacted>" if v not in (None, "", [], {}) else v
            elif kl in ("env", "environmentvariables") and isinstance(v, list):
                out[key] = [
                    {kk: vv for kk, vv in e.items() if kk in ("name", "secretRef")}
                    for e in v
                    if isinstance(e, dict)
                ]
            else:
                out[key] = sanitize(v, depth + 1)
        return out
    if isinstance(value, list):
        items = [sanitize(v, depth + 1) for v in value[:_MAX_LIST]]
        if len(value) > _MAX_LIST:
            items.append(f"<{len(value) - _MAX_LIST} more>")
        return items
    if isinstance(value, str) and len(value) > _MAX_STR:
        return value[:_MAX_STR] + "...<truncated>"
    return value


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """dict.get with a case-insensitive fallback (ARM key casing varies)."""
    if not isinstance(obj, dict):
        return default
    if key in obj:
        return obj[key]
    kl = key.lower()
    for k, v in obj.items():
        if isinstance(k, str) and k.lower() == kl:
            return v
    return default


def _path(obj: Any, *keys: str) -> Any:
    for key in keys:
        obj = _get(obj, key)
        if obj is None:
            return None
    return obj


def _rid(value: Any) -> str | None:
    if isinstance(value, dict):
        value = _get(value, "id")
    return value if isinstance(value, str) and value else None


def _rids(values: Any) -> list[str]:
    return [r for r in (_rid(v) for v in (values or [])) if r]


def _props(sub: Any) -> dict[str, Any]:
    """Properties of an embedded sub-resource (nested or already flattened)."""
    if not isinstance(sub, dict):
        return {}
    p = _get(sub, "properties")
    return p if isinstance(p, dict) else sub


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _lower(value: Any) -> str:
    return str(value).lower() if value is not None else ""


def _tags(tags: Any) -> dict[str, str]:
    if not isinstance(tags, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in tags.items()}


# ---------------------------------------------------------------------------
# Resource Graph querying
# ---------------------------------------------------------------------------


def default_graph_client_factory(credential: Any) -> Any:
    """Build a real ``ResourceGraphClient`` (raises ImportError when absent)."""
    from azure.mgmt.resourcegraph import ResourceGraphClient  # type: ignore[import-not-found]

    return ResourceGraphClient(credential)


def _make_request(
    query: str,
    subscriptions: list[str] | None,
    management_groups: list[str] | None,
    top: int,
    skip_token: str | None,
) -> Any:
    try:
        from azure.mgmt.resourcegraph.models import (  # type: ignore[import-not-found]
            QueryRequest,
            QueryRequestOptions,
        )

        options = QueryRequestOptions(top=top, skip_token=skip_token, result_format="objectArray")
        kwargs: dict[str, Any] = {"query": query, "options": options}
        if subscriptions:
            kwargs["subscriptions"] = subscriptions
        if management_groups:
            kwargs["management_groups"] = management_groups
        return QueryRequest(**kwargs)
    except ImportError:
        return SimpleNamespace(
            query=query,
            subscriptions=subscriptions,
            management_groups=management_groups,
            options=SimpleNamespace(top=top, skip_token=skip_token, result_format="objectArray"),
        )


def _rows_of(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, list):
        return [to_rest(r) if not isinstance(r, dict) else r for r in data]
    if isinstance(data, dict) and "rows" in data and "columns" in data:  # table format
        names = [c.get("name") for c in data.get("columns") or []]
        return [dict(zip(names, row)) for row in data.get("rows") or []]
    return []


def _status_code(exc: BaseException) -> int | None:
    code = getattr(exc, "status_code", None)
    if code is None:
        code = getattr(getattr(exc, "response", None), "status_code", None)
    return code if isinstance(code, int) else None


def run_query(
    client: Any,
    query: str,
    *,
    subscriptions: list[str] | None = None,
    management_groups: list[str] | None = None,
    page_size: int = 1000,
    max_pages: int = 5000,
    max_retries: int = 5,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """Run an ARG query across every page (``skip_token``).

    Retries throttled (HTTP 429) pages with exponential back-off. Blocking:
    call it from a worker thread inside async code.
    """
    rows: list[dict[str, Any]] = []
    skip: str | None = None
    for _ in range(max_pages):
        request = _make_request(query, subscriptions, management_groups, page_size, skip)
        attempt = 0
        while True:
            try:
                response = client.resources(request)
                break
            except Exception as exc:
                if _status_code(exc) == 429 and attempt < max_retries:
                    attempt += 1
                    sleep(min(2.0**attempt, 30.0))
                    continue
                raise
        rows.extend(_rows_of(getattr(response, "data", None)))
        skip = getattr(response, "skip_token", None)
        if not skip:
            break
    return rows


def resources_query(subscription_id: str) -> str:
    return (
        f"resources | where subscriptionId =~ '{_kql(subscription_id)}' "
        "| project id, name, type, kind, location, resourceGroup, subscriptionId, tags, sku, "
        "identity, managedBy, zones, plan, properties | order by id asc"
    )


def containers_query(subscription_id: str) -> str:
    return (
        f"resourcecontainers | where subscriptionId =~ '{_kql(subscription_id)}' "
        "| project id, name, type, location, resourceGroup, subscriptionId, tags, managedBy, properties "
        "| order by id asc"
    )


def role_assignments_query(subscription_id: str) -> str:
    guid = r"@'([0-9a-fA-F-]{36})$'"
    return (
        "authorizationresources "
        "| where type =~ 'microsoft.authorization/roleassignments' "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
        "| extend roleDefinitionId = tostring(properties.roleDefinitionId), "
        "principalId = tostring(properties.principalId), "
        "principalType = tostring(properties.principalType), scope = tostring(properties.scope) "
        f"| extend roleGuid = tolower(extract({guid}, 1, roleDefinitionId)) "
        "| join kind=leftouter (authorizationresources "
        "| where type =~ 'microsoft.authorization/roledefinitions' "
        f"| extend roleGuid = tolower(extract({guid}, 1, id)), roleName = tostring(properties.roleName) "
        "| summarize roleName = any(roleName) by roleGuid) on roleGuid "
        "| project id, name, roleDefinitionId, roleGuid, roleName, principalId, principalType, scope, "
        "properties | order by id asc"
    )


def defender_query(subscription_id: str) -> str:
    return (
        "securityresources | where type =~ 'microsoft.security/pricings' "
        f"| where subscriptionId =~ '{_kql(subscription_id)}' "
        "| project id, name, type, subscriptionId, properties | order by id asc"
    )


# ---------------------------------------------------------------------------
# Drafts and extractor registry
# ---------------------------------------------------------------------------


@dataclass
class _Draft:
    row: dict[str, Any]
    id: str
    type: str  # lowercase ARM type
    name: str
    props: dict[str, Any]
    asset_type: AssetType
    region: str
    account_id: str
    tags: dict[str, str]
    md: dict[str, Any] = field(default_factory=dict)
    relations: list[dict[str, Any]] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    exposed: bool = False
    synthetic: bool = False

    def add(self, *relations: dict[str, Any] | None) -> None:
        for r in relations:
            if r and r.get("target") and str(r["target"]).lower() != self.id.lower():
                self.relations.append(r)

    def alias(self, *values: Any) -> None:
        for v in values:
            if isinstance(v, str) and v and v not in self.aliases:
                self.aliases.append(v)


Extractor = Callable[["_Draft", "AzureAssetBuilder"], None]
_EXTRACTORS: dict[str, list[Extractor]] = {}

# Relationship of the parent -> child CONTAINS edge for nested types
_PARENT_RELATIONSHIP = {
    "microsoft.network/virtualnetworks/subnets": "VPC_CONTAINS_SUBNET",
    "microsoft.containerservice/managedclusters/agentpools": "CLUSTER_CONTAINS_SERVICE",
    "microsoft.web/sites/slots": "CLUSTER_CONTAINS_SERVICE",
    "microsoft.web/sites/functions": "CLUSTER_CONTAINS_SERVICE",
}


def extractor(*types: str) -> Callable[[Extractor], Extractor]:
    """Register a relation extractor for one or more lowercase ARM types."""

    def deco(fn: Extractor) -> Extractor:
        for t in types:
            _EXTRACTORS.setdefault(t.lower(), []).append(fn)
        return fn

    return deco


def _set_exposure(d: _Draft, default_public: bool = False) -> None:
    """PaaS exposure: public network access on and no default-deny ACL."""
    pna = _get(d.props, "publicNetworkAccess")
    acls = _get(d.props, "networkAcls") or _get(d.props, "networkRuleSet") or {}
    default_action = _get(acls, "defaultAction") if isinstance(acls, dict) else None
    if pna is not None:
        d.md["public_network_access"] = pna
    if default_action is not None:
        d.md["network_default_action"] = default_action
    if pna is None and not default_public:
        return
    enabled = pna is None or _lower(pna) == "enabled"
    if enabled and _lower(default_action or "allow") != "deny":
        d.exposed = True


def _network_rule_grants(d: _Draft, acls: Any) -> None:
    if not isinstance(acls, dict):
        return
    for vr in _list(_get(acls, "virtualNetworkRules")):
        subnet = _rid(vr) or _get(vr, "virtualNetworkResourceId")
        d.add(
            rel(
                subnet,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="virtual network rule",
                network_rule=True,
            )
        )
    for rr in _list(_get(acls, "resourceAccessRules")):
        d.add(
            rel(
                _get(rr, "resourceId"),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="resource instance rule",
                network_rule=True,
            )
        )
    ip_rules = [
        _get(r, "value") or _get(r, "ipAddressOrRange") for r in _list(_get(acls, "ipRules"))
    ]
    if any(ip_rules):
        d.md["ip_rules"] = [r for r in ip_rules if r]


def _keyvault_key_ref(d: _Draft, uri: Any, what: str = "customer-managed key") -> None:
    host = host_of(uri)
    if host and ".vault." in host:
        d.add(rel(host, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description=what, key_uri=uri))


# ── common extractors ──


def _common_identity(d: _Draft, b: "AzureAssetBuilder") -> None:
    identity = d.row.get("identity")
    if not isinstance(identity, dict):
        return
    principal = _get(identity, "principalId")
    user_assigned = _get(identity, "userAssignedIdentities") or {}
    d.md["identity"] = {
        "type": _get(identity, "type"),
        "principal_id": principal,
        "user_assigned": list(user_assigned.keys()) if isinstance(user_assigned, dict) else [],
    }
    if principal:
        d.alias(principal_ref(principal))
        b.register_principal(principal, d)
    if isinstance(user_assigned, dict):
        for uami_id in user_assigned:
            d.add(
                rel(
                    uami_id,
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description="user-assigned managed identity",
                )
            )


def _common_managed_by(d: _Draft, b: "AzureAssetBuilder") -> None:
    managed_by = d.row.get("managedBy")
    if not isinstance(managed_by, str) or not managed_by:
        return
    d.md["managed_by"] = managed_by
    if d.type == "microsoft.compute/disks":
        d.md["attached_instance_id"] = managed_by  # disks: managedBy == attached VM
        return
    d.add(rel(managed_by, EdgeType.MANAGES, "OWNED_BY", reverse=True, description="managedBy"))


def _common_parent(d: _Draft, b: "AzureAssetBuilder") -> None:
    if d.type in ("microsoft.resources/subscriptions",):
        return
    if d.type in (
        "microsoft.resources/subscriptions/resourcegroups",
        "microsoft.resources/resourcegroups",
    ):
        sub = subscription_of(d.id)
        if sub:
            d.add(
                rel(
                    subscription_ref(sub),
                    EdgeType.CONTAINS,
                    "ACCOUNT_CONTAINS_REGION",
                    reverse=True,
                )
            )
        return
    parent = parent_resource_id(d.id)
    if parent:
        d.md.setdefault("parent_resource", parent)
        d.add(rel(parent, EdgeType.CONTAINS, _PARENT_RELATIONSHIP.get(d.type), reverse=True))
        return
    rg = resource_group_of(d.id)
    if rg:
        d.add(rel(rg, EdgeType.CONTAINS, reverse=True, description="resource group"))
        return
    sub = subscription_of(d.id)
    if sub:
        d.add(rel(subscription_ref(sub), EdgeType.CONTAINS, reverse=True))


def _common_private_endpoint_connections(d: _Draft, b: "AzureAssetBuilder") -> None:
    for conn in _list(_get(d.props, "privateEndpointConnections")):
        pe = _rid(_get(_props(conn), "privateEndpoint"))
        state = _path(_props(conn), "privateLinkServiceConnectionState", "status")
        d.add(
            rel(
                pe,
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                reverse=True,
                description="private endpoint connection",
                status=state,
            )
        )


def _common_diagnostics(d: _Draft, b: "AzureAssetBuilder") -> None:
    ws = _get(d.props, "WorkspaceResourceId") or _get(d.props, "workspaceResourceId")
    if isinstance(ws, str) and ws.lower().startswith("/subscriptions/"):
        d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO"))


_COMMON: list[Extractor] = [
    _common_identity,
    _common_managed_by,
    _common_parent,
    _common_private_endpoint_connections,
    _common_diagnostics,
]


# ── networking ──


def _nsg_rule(rule: dict[str, Any], default: bool) -> dict[str, Any]:
    p = _props(rule)
    sources = [
        s for s in [_get(p, "sourceAddressPrefix")] + _list(_get(p, "sourceAddressPrefixes")) if s
    ]
    dests = [
        s
        for s in [_get(p, "destinationAddressPrefix")]
        + _list(_get(p, "destinationAddressPrefixes"))
        if s
    ]
    ports = [
        s for s in [_get(p, "destinationPortRange")] + _list(_get(p, "destinationPortRanges")) if s
    ]
    src_ports = [s for s in [_get(p, "sourcePortRange")] + _list(_get(p, "sourcePortRanges")) if s]
    return {
        "name": _get(rule, "name"),
        "priority": _get(p, "priority"),
        "direction": _get(p, "direction"),
        "access": _get(p, "access"),
        "protocol": _get(p, "protocol"),
        "source_address_prefix": _get(p, "sourceAddressPrefix"),
        "source_address_prefixes": sources,
        "source_application_security_groups": _rids(_get(p, "sourceApplicationSecurityGroups")),
        "destination_address_prefix": _get(p, "destinationAddressPrefix"),
        "destination_address_prefixes": dests,
        "destination_application_security_groups": _rids(
            _get(p, "destinationApplicationSecurityGroups")
        ),
        "destination_port_range": _get(p, "destinationPortRange"),
        "destination_port_ranges": ports,
        "source_port_ranges": src_ports,
        "default": default,
    }


@extractor("microsoft.network/networksecuritygroups")
def _x_nsg(d: _Draft, b: "AzureAssetBuilder") -> None:
    ingress: list[dict[str, Any]] = []
    egress: list[dict[str, Any]] = []
    for key, default in (("securityRules", False), ("defaultSecurityRules", True)):
        for rule in _list(_get(d.props, key)):
            if not isinstance(rule, dict):
                continue
            data = _nsg_rule(rule, default)
            (ingress if _lower(data["direction"]) == "inbound" else egress).append(data)
    d.md["ingress_rules"] = ingress
    d.md["egress_rules"] = egress
    d.md["subnet_ids"] = _rids(_get(d.props, "subnets"))
    d.md["network_interface_ids"] = _rids(_get(d.props, "networkInterfaces"))


@extractor("microsoft.network/virtualnetworks")
def _x_vnet(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["address_space"] = _list(_path(d.props, "addressSpace", "addressPrefixes"))
    ddos = _rid(_get(d.props, "ddosProtectionPlan"))
    d.add(rel(ddos, EdgeType.PROTECTS, reverse=True, description="DDoS protection plan"))
    subnet_ids: list[str] = []
    for sn in _list(_get(d.props, "subnets")):
        sid = _rid(sn)
        if not sid:
            continue
        subnet_ids.append(sid)
        b.add_row(
            {
                "id": sid,
                "name": _get(sn, "name") or sid.rsplit("/", 1)[-1],
                "type": "microsoft.network/virtualnetworks/subnets",
                "location": d.region,
                "subscriptionId": d.account_id,
                "properties": _props(sn),
            },
            synthetic=True,
            vnet_id=d.id,
        )
    d.md["subnet_ids"] = subnet_ids
    for peering in _list(_get(d.props, "virtualNetworkPeerings")):
        p = _props(peering)
        remote = _rid(_get(p, "remoteVirtualNetwork"))
        d.add(
            rel(
                remote,
                EdgeType.PEERING,
                "VPC_PEERED",
                description=f"peering {_get(peering, 'name')}",
                peering_state=_get(p, "peeringState"),
                allow_forwarded_traffic=_get(p, "allowForwardedTraffic"),
                allow_gateway_transit=_get(p, "allowGatewayTransit"),
                use_remote_gateways=_get(p, "useRemoteGateways"),
            )
        )
    # subnets become their own assets; keep the VNet bag small
    d.props = {k: v for k, v in d.props.items() if k != "subnets"}


@extractor("microsoft.network/virtualnetworks/subnets")
def _x_subnet(d: _Draft, b: "AzureAssetBuilder") -> None:
    prefixes = [
        p for p in [_get(d.props, "addressPrefix")] + _list(_get(d.props, "addressPrefixes")) if p
    ]
    d.md["address_prefix"] = prefixes[0] if prefixes else None
    d.md["address_prefixes"] = list(dict.fromkeys(prefixes))
    vnet = d.md.get("vnet_id") or parent_resource_id(d.id)
    d.md["vnet_id"] = vnet
    d.md["nsg_id"] = _rid(_get(d.props, "networkSecurityGroup"))
    rt = _rid(_get(d.props, "routeTable"))
    nat = _rid(_get(d.props, "natGateway"))
    d.md["route_table"] = rt
    d.md["nat_gateway"] = nat
    d.add(rel(rt, EdgeType.ATTACHED_TO, reverse=True, description="route table association"))
    d.add(rel(nat, EdgeType.ATTACHED_TO, "NAT_TRANSLATED", reverse=True, description="NAT gateway"))
    d.md["service_endpoints"] = [
        _get(se, "service")
        for se in _list(_get(d.props, "serviceEndpoints"))
        if _get(se, "service")
    ]
    d.md["delegations"] = [
        _get(_props(dl), "serviceName")
        for dl in _list(_get(d.props, "delegations"))
        if _get(_props(dl), "serviceName")
    ]
    d.md["private_endpoint_ids"] = _rids(_get(d.props, "privateEndpoints"))
    d.md["private_endpoint_network_policies"] = _get(d.props, "privateEndpointNetworkPolicies")
    # ipConfigurations lists every NIC in the subnet; NICs link themselves
    d.props = {
        k: v for k, v in d.props.items() if k not in ("ipConfigurations", "ipConfigurationProfiles")
    }


@extractor("microsoft.network/networkinterfaces")
def _x_nic(d: _Draft, b: "AzureAssetBuilder") -> None:
    subnets: list[str] = []
    private_ips: list[str] = []
    public_ips: list[str] = []
    for cfg in _list(_get(d.props, "ipConfigurations")):
        p = _props(cfg)
        d.alias(_rid(cfg))
        subnet = _rid(_get(p, "subnet"))
        if subnet and subnet not in subnets:
            subnets.append(subnet)
        ip = _get(p, "privateIPAddress")
        if ip:
            private_ips.append(ip)
        pip = _rid(_get(p, "publicIPAddress"))
        if pip:
            public_ips.append(pip)
            d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description="public IP"))
        for pool in _rids(_get(p, "loadBalancerBackendAddressPools")) + _rids(
            _get(p, "loadBalancerInboundNatRules")
        ):
            d.add(
                rel(
                    owner_resource_id(pool),
                    EdgeType.LOAD_BALANCER_TARGET,
                    "LB_TARGETS_INSTANCE",
                    reverse=True,
                    backend_pool=pool,
                )
            )
        for pool in _rids(_get(p, "applicationGatewayBackendAddressPools")):
            d.add(
                rel(
                    owner_resource_id(pool),
                    EdgeType.LOAD_BALANCER_TARGET,
                    "LB_TARGETS_INSTANCE",
                    reverse=True,
                    backend_pool=pool,
                )
            )
        for asg in _rids(_get(p, "applicationSecurityGroups")):
            if asg not in d.md.setdefault("security_groups", []):
                d.md["security_groups"].append(asg)
    for extra in subnets[1:]:
        d.add(rel(extra, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    vm = _rid(_get(d.props, "virtualMachine"))
    pe = _rid(_get(d.props, "privateEndpoint"))
    d.md.update(
        {
            "attached_instance_id": vm,
            "nsg_id": _rid(_get(d.props, "networkSecurityGroup")),
            "subnet_id": subnets[0] if subnets else None,
            "subnet_ids": subnets,
            "private_ip": private_ips[0] if private_ips else None,
            "private_ips": private_ips,
            "public_ip_id": public_ips[0] if public_ips else None,
            "public_ip_ids": public_ips,
            "private_endpoint_id": pe,
            "ip_forwarding": bool(_get(d.props, "enableIPForwarding")),
            "mac_address": _get(d.props, "macAddress"),
        }
    )
    if pe:
        d.add(rel(pe, EdgeType.ATTACHED_TO, description="private endpoint interface"))
    if d.md["ip_forwarding"]:
        d.alias(*private_ips)  # NVA next hops resolve to this interface
    if public_ips:
        d.exposed = True


@extractor("microsoft.network/publicipaddresses")
def _x_pip(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.exposed = True
    fqdn = _path(d.props, "dnsSettings", "fqdn")
    d.md.update(
        {
            "public_ip": _get(d.props, "ipAddress"),
            "allocation_method": _get(d.props, "publicIPAllocationMethod"),
            "fqdn": fqdn,
        }
    )
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    ipc = _rid(_get(d.props, "ipConfiguration"))
    d.add(rel(owner_resource_id(ipc), EdgeType.ATTACHED_TO, description="public IP association"))
    d.add(
        rel(
            _rid(_get(d.props, "natGateway")),
            EdgeType.ATTACHED_TO,
            description="NAT gateway public IP",
        )
    )


def _backend_targets(d: _Draft, pools: Any, waf: bool = False) -> None:
    backend_nics: list[str] = []
    backend_ips: list[str] = []
    for pool in _list(pools):
        p = _props(pool)
        d.alias(_rid(pool))
        for ipc in _rids(_get(p, "backendIPConfigurations")):
            owner = owner_resource_id(ipc)
            if owner and owner not in backend_nics:
                backend_nics.append(owner)
                d.add(
                    rel(
                        owner,
                        EdgeType.LOAD_BALANCER_TARGET,
                        "LB_TARGETS_INSTANCE",
                        backend_pool=_get(pool, "name"),
                    )
                )
        for addr in _list(_get(p, "loadBalancerBackendAddresses")):
            ap = _props(addr)
            ipc = _rid(_get(ap, "networkInterfaceIPConfiguration"))
            if ipc:
                d.add(
                    rel(
                        owner_resource_id(ipc),
                        EdgeType.LOAD_BALANCER_TARGET,
                        "LB_TARGETS_INSTANCE",
                        backend_pool=_get(pool, "name"),
                    )
                )
            ip = _get(ap, "ipAddress")
            if ip:
                backend_ips.append(ip)
                d.add(
                    rel(
                        ip,
                        EdgeType.LOAD_BALANCER_TARGET,
                        "LB_TARGETS_INSTANCE",
                        backend_pool=_get(pool, "name"),
                    )
                )
        for addr in _list(_get(p, "backendAddresses")):  # application gateway
            target = _get(addr, "fqdn") or _get(addr, "ipAddress")
            if target:
                backend_ips.append(target)
                ref = target.lower() if _get(addr, "fqdn") else target
                d.add(
                    rel(
                        ref,
                        EdgeType.LOAD_BALANCER_TARGET,
                        "SERVES_TRAFFIC_TO",
                        backend_pool=_get(pool, "name"),
                    )
                )
    d.md["backend_network_interfaces"] = backend_nics
    d.md["backend_addresses"] = backend_ips


def _frontends(d: _Draft, configs: Any) -> None:
    public: list[str] = []
    for fe in _list(configs):
        p = _props(fe)
        d.alias(_rid(fe))
        pip = _rid(_get(p, "publicIPAddress"))
        if pip:
            public.append(pip)
            d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description="frontend public IP"))
        subnet = _rid(_get(p, "subnet"))
        d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
        ip = _get(p, "privateIPAddress")
        if ip:
            d.alias(ip)
    d.md["frontend_public_ip_ids"] = public
    if public:
        d.exposed = True


@extractor("microsoft.network/loadbalancers")
def _x_lb(d: _Draft, b: "AzureAssetBuilder") -> None:
    sku = d.row.get("sku")
    d.md["sku"] = _get(sku, "name") if isinstance(sku, dict) else sku
    _frontends(d, _get(d.props, "frontendIPConfigurations"))
    _backend_targets(d, _get(d.props, "backendAddressPools"))
    for rule in _list(_get(d.props, "inboundNatRules")):
        d.alias(_rid(rule))


@extractor("microsoft.network/applicationgateways")
def _x_appgw(d: _Draft, b: "AzureAssetBuilder") -> None:
    _frontends(d, _get(d.props, "frontendIPConfigurations"))
    for gw in _list(_get(d.props, "gatewayIPConfigurations")):
        d.add(
            rel(
                _rid(_get(_props(gw), "subnet")),
                EdgeType.CONTAINS,
                "SUBNET_CONTAINS_INSTANCE",
                reverse=True,
            )
        )
    _backend_targets(d, _get(d.props, "backendAddressPools"))
    policy = _rid(_get(d.props, "firewallPolicy"))
    d.add(
        rel(policy, EdgeType.PROTECTS, "PROTECTED_BY_WAF", reverse=True, description="WAF policy")
    )
    waf = _get(d.props, "webApplicationFirewallConfiguration")
    d.md["waf_enabled"] = bool(policy) or bool(_get(waf, "enabled"))
    for cert in _list(_get(d.props, "sslCertificates")):
        secret = _get(_props(cert), "keyVaultSecretId")
        host = host_of(secret)
        d.add(
            rel(
                host,
                EdgeType.REFERENCES,
                "CERTIFICATE_SECURES",
                description="TLS certificate from Key Vault",
            )
        )


@extractor("microsoft.network/azurefirewalls")
def _x_firewall(d: _Draft, b: "AzureAssetBuilder") -> None:
    for cfg in _list(_get(d.props, "ipConfigurations")) + _list(
        _get(d.props, "managementIpConfiguration")
    ):
        p = _props(cfg)
        d.alias(_rid(cfg))
        d.add(
            rel(
                _rid(_get(p, "subnet")), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True
            )
        )
        pip = _rid(_get(p, "publicIPAddress"))
        if pip:
            d.exposed = True
            d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description="firewall public IP"))
        if _get(p, "privateIPAddress"):
            d.alias(_get(p, "privateIPAddress"))
            d.md["private_ip"] = _get(p, "privateIPAddress")
    hub_ip = _path(d.props, "hubIPAddresses", "privateIPAddress")
    d.alias(hub_ip)
    d.add(
        rel(
            _rid(_get(d.props, "firewallPolicy")),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="firewall policy",
        )
    )
    d.add(rel(_rid(_get(d.props, "virtualHub")), EdgeType.CONTAINS, reverse=True))


@extractor("microsoft.network/firewallpolicies")
def _x_firewall_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(
        rel(
            _rid(_get(d.props, "basePolicy")),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="base policy",
        )
    )


@extractor("microsoft.network/routetables")
def _x_route_table(d: _Draft, b: "AzureAssetBuilder") -> None:
    routes = []
    for route in _list(_get(d.props, "routes")):
        p = _props(route)
        entry = {
            "name": _get(route, "name"),
            "address_prefix": _get(p, "addressPrefix"),
            "next_hop_type": _get(p, "nextHopType"),
            "next_hop_ip": _get(p, "nextHopIpAddress"),
        }
        routes.append(entry)
        if entry["next_hop_ip"]:
            d.add(
                rel(
                    entry["next_hop_ip"],
                    EdgeType.ROUTE,
                    "TRANSIT_ROUTED",
                    description=f"route {entry['address_prefix']} via {entry['next_hop_ip']}",
                    address_prefix=entry["address_prefix"],
                    next_hop_type=entry["next_hop_type"],
                )
            )
        if _lower(entry["next_hop_type"]) == "internet" and entry["address_prefix"] in (
            "0.0.0.0/0",
            "::/0",
        ):
            d.md["default_route_to_internet"] = True
    d.md["routes"] = routes
    d.md["subnet_ids"] = _rids(_get(d.props, "subnets"))
    for sn in d.md["subnet_ids"]:
        d.add(rel(sn, EdgeType.ATTACHED_TO, description="route table association"))
    d.md["bgp_route_propagation_disabled"] = _get(d.props, "disableBgpRoutePropagation")


@extractor("microsoft.network/natgateways")
def _x_nat(d: _Draft, b: "AzureAssetBuilder") -> None:
    for pip in _rids(_get(d.props, "publicIpAddresses")) + _rids(_get(d.props, "publicIpPrefixes")):
        d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True, description="NAT gateway public IP"))
    for sn in _rids(_get(d.props, "subnets")):
        d.add(rel(sn, EdgeType.ATTACHED_TO, "NAT_TRANSLATED", description="NAT gateway"))


@extractor("microsoft.network/privateendpoints")
def _x_private_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    subnet = _rid(_get(d.props, "subnet"))
    d.md["subnet_id"] = subnet
    d.md["network_interfaces"] = _rids(_get(d.props, "networkInterfaces"))
    targets = []
    for key in ("privateLinkServiceConnections", "manualPrivateLinkServiceConnections"):
        for conn in _list(_get(d.props, key)):
            p = _props(conn)
            target = _get(p, "privateLinkServiceId")
            groups = _list(_get(p, "groupIds"))
            if target:
                targets.append({"target": target, "group_ids": groups})
            d.add(
                rel(
                    target,
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="private link",
                    group_ids=groups,
                    manual=key.startswith("manual"),
                    status=_path(p, "privateLinkServiceConnectionState", "status"),
                )
            )
    d.md["private_link_targets"] = targets
    fqdns = [_get(c, "fqdn") for c in _list(_get(d.props, "customDnsConfigs")) if _get(c, "fqdn")]
    d.md["fqdns"] = fqdns


@extractor("microsoft.network/privatelinkservices")
def _x_pls(d: _Draft, b: "AzureAssetBuilder") -> None:
    for fe in _rids(_get(d.props, "loadBalancerFrontendIpConfigurations")):
        d.add(
            rel(
                owner_resource_id(fe),
                EdgeType.REFERENCES,
                "SERVES_TRAFFIC_TO",
                description="load balancer frontend",
            )
        )
    for cfg in _list(_get(d.props, "ipConfigurations")):
        d.add(
            rel(
                _rid(_get(_props(cfg), "subnet")),
                EdgeType.CONTAINS,
                "SUBNET_CONTAINS_INSTANCE",
                reverse=True,
            )
        )


@extractor("microsoft.network/virtualnetworkgateways", "microsoft.network/bastionhosts")
def _x_vnet_gateway(d: _Draft, b: "AzureAssetBuilder") -> None:
    for cfg in _list(_get(d.props, "ipConfigurations")):
        p = _props(cfg)
        d.alias(_rid(cfg))
        d.add(
            rel(
                _rid(_get(p, "subnet")), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True
            )
        )
        pip = _rid(_get(p, "publicIPAddress"))
        if pip:
            d.exposed = True
            d.add(rel(pip, EdgeType.ATTACHED_TO, reverse=True))


@extractor("microsoft.network/connections")
def _x_connection(d: _Draft, b: "AzureAssetBuilder") -> None:
    for key in ("virtualNetworkGateway1", "virtualNetworkGateway2", "localNetworkGateway2"):
        d.add(rel(_rid(_get(d.props, key)), EdgeType.ATTACHED_TO, "TRANSIT_ROUTED"))
    d.add(rel(_rid(_get(d.props, "peer")), EdgeType.ATTACHED_TO, "TRANSIT_ROUTED"))
    d.md["connection_type"] = _get(d.props, "connectionType")


@extractor("microsoft.network/privatednszones/virtualnetworklinks")
def _x_dns_link(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(
        rel(
            _rid(_get(d.props, "virtualNetwork")),
            EdgeType.REFERENCES,
            "DNS_RESOLVED",
            registration_enabled=_get(d.props, "registrationEnabled"),
        )
    )


@extractor("microsoft.network/networkwatchers/flowlogs")
def _x_flow_log(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.add(
        rel(
            _get(d.props, "targetResourceId"),
            EdgeType.MONITORS,
            "MONITORED_BY",
            description="flow logging",
        )
    )
    d.add(rel(_get(d.props, "storageId"), EdgeType.LOGS_TO, "LOGS_TO"))
    ws = _path(
        d.props,
        "flowAnalyticsConfiguration",
        "networkWatcherFlowAnalyticsConfiguration",
        "workspaceResourceId",
    )
    d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO", description="traffic analytics"))


@extractor("microsoft.network/frontdoors")
def _x_front_door_classic(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.exposed = True
    for fe in _list(_get(d.props, "frontendEndpoints")):
        p = _props(fe)
        d.alias(_get(p, "hostName").lower() if isinstance(_get(p, "hostName"), str) else None)
        waf = _rid(_get(p, "webApplicationFirewallPolicyLink"))
        d.add(rel(waf, EdgeType.PROTECTS, "PROTECTED_BY_WAF", reverse=True))
    for pool in _list(_get(d.props, "backendPools")):
        for backend in _list(_get(_props(pool), "backends")):
            addr = _get(backend, "address")
            d.add(
                rel(
                    addr.lower() if isinstance(addr, str) else None,
                    EdgeType.LOAD_BALANCER_TARGET,
                    "SERVES_TRAFFIC_TO",
                    backend_pool=_get(pool, "name"),
                )
            )
            d.add(
                rel(
                    _get(backend, "privateLinkResourceId"),
                    EdgeType.LOAD_BALANCER_TARGET,
                    "SERVES_TRAFFIC_TO",
                )
            )


@extractor(
    "microsoft.cdn/profiles/afdendpoints",
    "microsoft.cdn/profiles/endpoints",
    "microsoft.cdn/profiles/customdomains",
)
def _x_cdn_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.exposed = True
    host = _get(d.props, "hostName")
    d.alias(host.lower() if isinstance(host, str) else None)
    for origin in _list(_get(d.props, "origins")):  # classic CDN endpoint
        oh = _get(_props(origin), "hostName")
        d.add(
            rel(
                oh.lower() if isinstance(oh, str) else None,
                EdgeType.LOAD_BALANCER_TARGET,
                "SERVES_TRAFFIC_TO",
            )
        )


@extractor("microsoft.cdn/profiles/origingroups/origins")
def _x_afd_origin(d: _Draft, b: "AzureAssetBuilder") -> None:
    host = _get(d.props, "hostName")
    target = _rid(_get(d.props, "azureOrigin")) or (host.lower() if isinstance(host, str) else None)
    d.add(
        rel(
            target,
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
            description="Front Door origin",
        )
    )


@extractor("microsoft.cdn/profiles/securitypolicies")
def _x_afd_security_policy(d: _Draft, b: "AzureAssetBuilder") -> None:
    params = _get(d.props, "parameters") or {}
    waf = _rid(_get(params, "wafPolicy"))
    d.add(rel(waf, EdgeType.REFERENCES, "DEPENDS_ON"))
    for assoc in _list(_get(params, "associations")):
        for domain in _rids(_get(assoc, "domains")):
            d.add(rel(domain, EdgeType.PROTECTS, "PROTECTED_BY_WAF"))
            if waf:
                b.defer(
                    waf,
                    rel(
                        domain, EdgeType.PROTECTS, "PROTECTED_BY_WAF", description="Front Door WAF"
                    ),
                )


# ── compute ──


@extractor("microsoft.compute/virtualmachines")
def _x_vm(d: _Draft, b: "AzureAssetBuilder") -> None:
    storage = _get(d.props, "storageProfile") or {}
    os_disk = _get(storage, "osDisk") or {}
    d.md.update(
        {
            "vm_size": _path(d.props, "hardwareProfile", "vmSize"),
            "os_type": _get(os_disk, "osType"),
            "provisioning_state": _get(d.props, "provisioningState"),
            "network_interfaces": _rids(_path(d.props, "networkProfile", "networkInterfaces")),
            "computer_name": _path(d.props, "osProfile", "computerName"),
            "power_state": _path(d.props, "extended", "instanceView", "powerState", "code"),
        }
    )
    disks = [_rid(_get(os_disk, "managedDisk"))] + [
        _rid(_get(dd, "managedDisk")) for dd in _list(_get(storage, "dataDisks"))
    ]
    for disk in disks:
        d.add(rel(disk, EdgeType.ATTACHED_TO, reverse=True, description="managed disk"))
    image = _rid(_get(storage, "imageReference"))
    d.add(rel(image, EdgeType.USES_IMAGE, "RUNS_ON", description="VM image"))
    d.add(rel(_rid(_get(d.props, "availabilitySet")), EdgeType.CONTAINS, reverse=True))
    d.add(
        rel(
            _rid(_get(d.props, "virtualMachineScaleSet")),
            EdgeType.CONTAINS,
            "SCALES_WITH",
            reverse=True,
        )
    )
    d.add(rel(_rid(_get(d.props, "proximityPlacementGroup")), EdgeType.REFERENCES, "DEPENDS_ON"))


@extractor("microsoft.compute/virtualmachinescalesets")
def _x_vmss(d: _Draft, b: "AzureAssetBuilder") -> None:
    profile = _get(d.props, "virtualMachineProfile") or {}
    for nic_cfg in _list(_path(profile, "networkProfile", "networkInterfaceConfigurations")):
        np = _props(nic_cfg)
        d.add(rel(_rid(_get(np, "networkSecurityGroup")), EdgeType.ATTACHED_TO, "PROTECTED_BY_SG"))
        for ipc in _list(_get(np, "ipConfigurations")):
            p = _props(ipc)
            d.add(
                rel(
                    _rid(_get(p, "subnet")),
                    EdgeType.CONTAINS,
                    "SUBNET_CONTAINS_INSTANCE",
                    reverse=True,
                )
            )
            for pool in _rids(_get(p, "loadBalancerBackendAddressPools")) + _rids(
                _get(p, "applicationGatewayBackendAddressPools")
            ):
                d.add(
                    rel(
                        owner_resource_id(pool),
                        EdgeType.LOAD_BALANCER_TARGET,
                        "LB_TARGETS_INSTANCE",
                        reverse=True,
                    )
                )
            for asg in _rids(_get(p, "applicationSecurityGroups")):
                d.add(rel(asg, EdgeType.ATTACHED_TO, "PROTECTED_BY_SG"))
    d.add(
        rel(
            _rid(_path(profile, "storageProfile", "imageReference")), EdgeType.USES_IMAGE, "RUNS_ON"
        )
    )
    sku = d.row.get("sku")
    d.md["capacity"] = _get(sku, "capacity") if isinstance(sku, dict) else None


@extractor("microsoft.compute/disks")
def _x_disk(d: _Draft, b: "AzureAssetBuilder") -> None:
    enc = _get(d.props, "encryption") or {}
    des = _get(enc, "diskEncryptionSetId")
    d.md.update(
        {
            "size_gb": _get(d.props, "diskSizeGB"),
            "state": _get(d.props, "diskState"),
            "encryption": _get(enc, "type"),
            "disk_encryption_set": des,
            "network_access_policy": _get(d.props, "networkAccessPolicy"),
        }
    )
    d.md.setdefault("attached_instance_id", d.row.get("managedBy"))
    d.add(rel(des, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description="disk encryption set"))
    d.add(
        rel(
            _path(d.props, "creationData", "sourceResourceId"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="created from",
        )
    )


@extractor("microsoft.compute/diskencryptionsets")
def _x_des(d: _Draft, b: "AzureAssetBuilder") -> None:
    key = _get(d.props, "activeKey") or {}
    vault = _rid(_get(key, "sourceVault"))
    d.md["key_url"] = _get(key, "keyUrl")
    d.add(rel(vault, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description="key vault key"))
    if not vault:
        _keyvault_key_ref(d, _get(key, "keyUrl"))


# ── containers / app platform ──


@extractor("microsoft.containerservice/managedclusters")
def _x_aks(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    kubelet = _path(p, "identityProfile", "kubeletidentity") or {}
    kubelet_id = _get(kubelet, "resourceId")
    kubelet_oid = _get(kubelet, "objectId")
    d.md["kubelet_identity"] = {
        "resource_id": kubelet_id,
        "object_id": kubelet_oid,
        "client_id": _get(kubelet, "clientId"),
    }
    d.add(rel(kubelet_id, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="kubelet identity"))
    if kubelet_oid:
        b.register_kubelet(kubelet_oid, d)
    addons = _get(p, "addonProfiles") or {}
    oms = _get(addons, "omsagent") or _get(addons, "omsAgent") or {}
    ws = _get(_get(oms, "config") or {}, "logAnalyticsWorkspaceResourceID")
    if _get(oms, "enabled") is not False:
        d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO", description="Container Insights"))
    ws2 = _path(p, "azureMonitorProfile", "containerInsights", "logAnalyticsWorkspaceResourceId")
    d.add(rel(ws2, EdgeType.LOGS_TO, "LOGS_TO", description="Container Insights"))
    defender_ws = _path(p, "securityProfile", "defender", "logAnalyticsWorkspaceResourceId")
    d.add(rel(defender_ws, EdgeType.LOGS_TO, "LOGS_TO", description="Defender for Containers"))
    agic = _get(_get(addons, "ingressApplicationGateway") or {}, "config") or {}
    appgw = _get(agic, "effectiveApplicationGatewayId") or _get(agic, "applicationGatewayId")
    d.add(
        rel(
            appgw,
            EdgeType.REFERENCES,
            "SERVES_TRAFFIC_TO",
            reverse=True,
            description="AGIC ingress",
        )
    )
    node_rg = _get(p, "nodeResourceGroup")
    if node_rg:
        d.md["node_resource_group"] = node_rg
        d.add(
            rel(
                f"/subscriptions/{d.account_id}/resourceGroups/{node_rg}",
                EdgeType.MANAGES,
                "OWNED_BY",
                description="node resource group",
            )
        )
    api = _get(p, "apiServerAccessProfile") or {}
    private = bool(_get(api, "enablePrivateCluster"))
    authorized = _list(_get(api, "authorizedIPRanges"))
    d.md.update(
        {
            "kubernetes_version": _get(p, "kubernetesVersion")
            or _get(p, "currentKubernetesVersion"),
            "fqdn": _get(p, "fqdn"),
            "private_fqdn": _get(p, "privateFQDN"),
            "private_cluster": private,
            "api_server_authorized_ip_ranges": authorized,
            "network_plugin": _path(p, "networkProfile", "networkPlugin"),
            "network_policy": _path(p, "networkProfile", "networkPolicy"),
            "outbound_type": _path(p, "networkProfile", "outboundType"),
            "aad_managed": _path(p, "aadProfile", "managed"),
            "azure_rbac": _path(p, "aadProfile", "enableAzureRBAC"),
            "local_accounts_disabled": _get(p, "disableLocalAccounts"),
            "rbac_enabled": _get(p, "enableRBAC"),
        }
    )
    for host in (_get(p, "fqdn"), _get(p, "privateFQDN")):
        d.alias(host.lower() if isinstance(host, str) else None)
    if not private and _get(p, "fqdn"):
        d.exposed = True
    for out_ip in _rids(_path(p, "networkProfile", "loadBalancerProfile", "effectiveOutboundIPs")):
        d.add(rel(out_ip, EdgeType.ATTACHED_TO, reverse=True, description="egress public IP"))
    for pool in _list(_get(p, "agentPoolProfiles")):
        name = _get(pool, "name")
        if not name:
            continue
        b.add_row(
            {
                "id": f"{d.id}/agentPools/{name}",
                "name": name,
                "type": "microsoft.containerservice/managedclusters/agentpools",
                "location": d.region,
                "subscriptionId": d.account_id,
                "tags": _get(pool, "tags") or {},
                "properties": pool,
            },
            synthetic=True,
        )


@extractor("microsoft.containerservice/managedclusters/agentpools")
def _x_agent_pool(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    subnet = _get(p, "vnetSubnetID")
    pod_subnet = _get(p, "podSubnetID")
    d.md.update(
        {
            "vm_size": _get(p, "vmSize"),
            "count": _get(p, "count"),
            "mode": _get(p, "mode"),
            "os_type": _get(p, "osType"),
            "vnet_subnet_id": subnet,
            "pod_subnet_id": pod_subnet,
            "public_node_ips": _get(p, "enableNodePublicIP"),
            "cluster_id": parent_resource_id(d.id),
        }
    )
    d.add(
        rel(
            subnet,
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
            description="node subnet",
        )
    )
    d.add(
        rel(
            pod_subnet,
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
            description="pod subnet",
        )
    )
    if _get(p, "enableNodePublicIP"):
        d.exposed = True


@extractor("microsoft.containerregistry/registries")
def _x_acr(d: _Draft, b: "AzureAssetBuilder") -> None:
    login = _get(d.props, "loginServer")
    if isinstance(login, str):
        d.alias(login.lower())
        d.md["login_server"] = login.lower()
    d.md["admin_user_enabled"] = _get(d.props, "adminUserEnabled")
    _set_exposure(d, default_public=True)
    enc = _path(d.props, "encryption", "keyVaultProperties", "keyIdentifier")
    _keyvault_key_ref(d, enc)


def _image_relations(d: _Draft, images: Iterable[Any]) -> None:
    seen: list[str] = []
    for image in images:
        host = registry_host(image)
        if host and host not in seen:
            seen.append(host)
            d.add(
                rel(host, EdgeType.USES_IMAGE, "RUNS_ON", description=f"runs {image}", image=image)
            )
    if seen or images:
        d.md["images"] = [i for i in images if i]


@extractor("microsoft.web/sites", "microsoft.web/sites/slots")
def _x_site(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    kind = _lower(d.row.get("kind"))
    d.md["role"] = (
        "function" if "functionapp" in kind else ("workflow" if "workflowapp" in kind else "web")
    )
    d.add(
        rel(
            _get(p, "serverFarmId"),
            EdgeType.CONTAINS,
            "CLUSTER_CONTAINS_SERVICE",
            reverse=True,
            description="App Service plan",
        )
    )
    subnet = _get(p, "virtualNetworkSubnetId")
    d.md["vnet_integration_subnet"] = subnet
    d.add(rel(subnet, EdgeType.ATTACHED_TO, description="VNet integration"))
    d.add(rel(_rid(_get(p, "hostingEnvironmentProfile")), EdgeType.CONTAINS, reverse=True))
    fx: list[Any] = []
    site_config = _get(p, "siteConfig") or {}
    fx += [_get(site_config, "linuxFxVersion"), _get(site_config, "windowsFxVersion")]
    for item in _list(_path(p, "siteProperties", "properties")):
        if _lower(_get(item, "name")) in ("linuxfxversion", "windowsfxversion"):
            fx.append(_get(item, "value"))
    images = [i for i in (_docker_image(v) for v in fx) if i]
    _image_relations(d, list(dict.fromkeys(images)))
    kv_identity = _get(p, "keyVaultReferenceIdentity")
    if isinstance(kv_identity, str) and kv_identity.lower().startswith("/subscriptions/"):
        d.add(
            rel(
                kv_identity,
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="Key Vault reference identity",
            )
        )
    hosts = (
        [_get(p, "defaultHostName")]
        + _list(_get(p, "enabledHostNames"))
        + _list(_get(p, "hostNames"))
    )
    for host in hosts:
        d.alias(host.lower() if isinstance(host, str) else None)
    d.md["default_host_name"] = _get(p, "defaultHostName")
    d.md["https_only"] = _get(p, "httpsOnly")
    d.md["state"] = _get(p, "state")
    pna = _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    if _lower(pna) != "disabled":
        d.exposed = True


@extractor("microsoft.web/serverfarms")
def _x_plan(d: _Draft, b: "AzureAssetBuilder") -> None:
    sku = d.row.get("sku") or {}
    d.md.update(
        {
            "role": "plan",
            "tier": _get(sku, "tier") if isinstance(sku, dict) else None,
            "workers": _get(d.props, "numberOfWorkers")
            or (_get(sku, "capacity") if isinstance(sku, dict) else None),
            "site_count": _get(d.props, "numberOfSites"),
        }
    )
    d.add(rel(_rid(_get(d.props, "hostingEnvironmentProfile")), EdgeType.CONTAINS, reverse=True))


@extractor("microsoft.web/hostingenvironments")
def _x_ase(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["role"] = "environment"
    subnet = _rid(_path(d.props, "virtualNetwork")) or _path(d.props, "virtualNetwork", "id")
    d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))


@extractor("microsoft.app/containerapps", "microsoft.app/jobs")
def _x_container_app(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    env = _get(p, "managedEnvironmentId") or _get(p, "environmentId")
    d.add(
        rel(
            env,
            EdgeType.CONTAINS,
            "CLUSTER_CONTAINS_SERVICE",
            reverse=True,
            description="Container Apps environment",
        )
    )
    template = _get(p, "template") or {}
    images = [
        _get(c, "image")
        for c in _list(_get(template, "containers")) + _list(_get(template, "initContainers"))
    ]
    _image_relations(d, [i for i in images if i])
    config = _get(p, "configuration") or {}
    for reg in _list(_get(config, "registries")):
        server = _get(reg, "server")
        if isinstance(server, str):
            d.add(
                rel(
                    server.lower(),
                    EdgeType.USES_IMAGE,
                    "RUNS_ON",
                    description="configured registry",
                )
            )
        ident = _get(reg, "identity")
        if isinstance(ident, str) and ident.lower().startswith("/subscriptions/"):
            d.add(
                rel(ident, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="registry pull identity")
            )
    ingress = _get(config, "ingress") or {}
    fqdn = _get(ingress, "fqdn") or _get(p, "latestRevisionFqdn")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    d.md["ingress_external"] = _get(ingress, "external")
    if _get(ingress, "external"):
        d.exposed = True


@extractor("microsoft.app/managedenvironments")
def _x_container_env(d: _Draft, b: "AzureAssetBuilder") -> None:
    vnet = _get(d.props, "vnetConfiguration") or {}
    d.add(
        rel(
            _get(vnet, "infrastructureSubnetId"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    d.md["internal"] = _get(vnet, "internal")
    customer = _path(d.props, "appLogsConfiguration", "logAnalyticsConfiguration", "customerId")
    if customer:
        d.add(rel(f"{LOG_ANALYTICS_PREFIX}{customer.lower()}", EdgeType.LOGS_TO, "LOGS_TO"))
    domain = _get(d.props, "defaultDomain")
    d.md["default_domain"] = domain
    d.md["static_ip"] = _get(d.props, "staticIp")


@extractor("microsoft.containerinstance/containergroups")
def _x_aci(d: _Draft, b: "AzureAssetBuilder") -> None:
    images = [_get(_props(c), "image") for c in _list(_get(d.props, "containers"))]
    _image_relations(d, [i for i in images if i])
    for cred in _list(_get(d.props, "imageRegistryCredentials")):
        server = _get(cred, "server")
        if isinstance(server, str):
            d.add(
                rel(
                    server.lower(),
                    EdgeType.USES_IMAGE,
                    "RUNS_ON",
                    description="configured registry",
                )
            )
    for sn in _rids(_get(d.props, "subnetIds")):
        d.add(rel(sn, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    ip = _get(d.props, "ipAddress") or {}
    if _lower(_get(ip, "type")) == "public":
        d.exposed = True
        d.md["public_ip"] = _get(ip, "ip")
        fqdn = _get(ip, "fqdn")
        d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    ws = _path(d.props, "diagnostics", "logAnalytics", "workspaceResourceId")
    d.add(rel(ws, EdgeType.LOGS_TO, "LOGS_TO"))
    cust = _path(d.props, "diagnostics", "logAnalytics", "workspaceId")
    if cust:
        d.add(rel(f"{LOG_ANALYTICS_PREFIX}{str(cust).lower()}", EdgeType.LOGS_TO, "LOGS_TO"))


@extractor("microsoft.apimanagement/service")
def _x_apim(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    subnet = _path(p, "virtualNetworkConfiguration", "subnetResourceId")
    d.add(rel(subnet, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    d.add(rel(_get(p, "publicIpAddressId"), EdgeType.ATTACHED_TO, reverse=True))
    vnet_type = _get(p, "virtualNetworkType")
    d.md["virtual_network_type"] = vnet_type
    for url in (_get(p, "gatewayUrl"), _get(p, "developerPortalUrl"), _get(p, "managementApiUrl")):
        d.alias(host_of(url))
    for hc in _list(_get(p, "hostnameConfigurations")):
        d.alias(host_of(_get(hc, "hostName")))
        kv = host_of(_get(hc, "keyVaultId"))
        d.add(
            rel(
                kv,
                EdgeType.REFERENCES,
                "CERTIFICATE_SECURES",
                description="custom domain certificate",
            )
        )
    if (
        _lower(vnet_type) != "internal"
        and _lower(_get(p, "publicNetworkAccess") or "enabled") != "disabled"
    ):
        d.exposed = True


# ── data / security ──


@extractor("microsoft.keyvault/vaults")
def _x_key_vault(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    uri = _get(p, "vaultUri")
    host = host_of(uri)
    d.alias(host, uri, uri.rstrip("/") if isinstance(uri, str) else None)
    d.md.update(
        {
            "vault_uri": uri,
            "rbac_authorization": _get(p, "enableRbacAuthorization"),
            "soft_delete": _get(p, "enableSoftDelete"),
            "purge_protection": _get(p, "enablePurgeProtection"),
        }
    )
    policies = []
    for ap in _list(_get(p, "accessPolicies")):
        oid = _get(ap, "objectId")
        perms = _get(ap, "permissions") or {}
        policies.append({"object_id": oid, "permissions": perms})
        principal = principal_ref(oid)
        if principal:
            b.note_principal(oid, None)
            d.add(
                rel(
                    principal,
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description="Key Vault access policy",
                    keys=_get(perms, "keys"),
                    secrets=_get(perms, "secrets"),
                    certificates=_get(perms, "certificates"),
                )
            )
    d.md["access_policies"] = policies
    _network_rule_grants(d, _get(p, "networkAcls"))
    _set_exposure(d, default_public=True)


@extractor("microsoft.storage/storageaccounts")
def _x_storage(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    sku = d.row.get("sku")
    d.md.update(
        {
            "kind": d.row.get("kind"),
            "sku": _get(sku, "name") if isinstance(sku, dict) else sku,
            "https_only": _get(p, "supportsHttpsTrafficOnly"),
            "access_tier": _get(p, "accessTier"),
            "provisioning_state": _get(p, "provisioningState"),
            "public_blob_access": _get(p, "allowBlobPublicAccess"),
            "shared_key_access": _get(p, "allowSharedKeyAccess"),
            "min_tls_version": _get(p, "minimumTlsVersion"),
            "hns_enabled": _get(p, "isHnsEnabled"),
        }
    )
    for endpoint in (_get(p, "primaryEndpoints") or {}).values():
        d.alias(host_of(endpoint))
    _network_rule_grants(d, _get(p, "networkAcls"))
    enc = _get(p, "encryption") or {}
    if _lower(_get(enc, "keySource")) == "microsoft.keyvault":
        _keyvault_key_ref(d, _path(enc, "keyvaultproperties", "keyvaulturi"))
    uai = _path(enc, "identity", "userAssignedIdentity")
    d.add(rel(uai, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="encryption identity"))
    _set_exposure(d, default_public=True)
    if _get(p, "allowBlobPublicAccess"):
        d.md["anonymous_access_possible"] = True


@extractor("microsoft.sql/servers")
def _x_sql_server(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    fqdn = _get(p, "fullyQualifiedDomainName")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    admins = _get(p, "administrators") or {}
    d.md.update(
        {
            "role": "server",
            "server_name": d.name,
            "resource_group": resource_group_of(d.id).rsplit("/", 1)[-1]
            if resource_group_of(d.id)
            else None,
            "fqdn": fqdn,
            "version": _get(p, "version"),
            "minimal_tls_version": _get(p, "minimalTlsVersion"),
            "entra_only_auth": _get(admins, "azureADOnlyAuthentication"),
        }
    )
    sid = _get(admins, "sid")
    if sid:
        b.note_principal(sid, _get(admins, "principalType"))
        d.add(
            rel(
                principal_ref(sid),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="Entra administrator",
                role="SQL Entra admin",
                privileged=True,
            )
        )
    _keyvault_key_ref(d, _get(p, "keyId"))
    # firewall / vnet rules (present on the SDK fallback path)
    fw = _list(_get(p, "firewallRules"))
    internet_rules = []
    for rule in fw:
        rp = _props(rule)
        start, end = _get(rp, "startIpAddress"), _get(rp, "endIpAddress")
        if start == "0.0.0.0" and end == "0.0.0.0":
            d.md["allow_azure_services"] = True
        elif start:
            internet_rules.append({"name": _get(rule, "name"), "start": start, "end": end})
    if fw:
        d.md["firewall_rules"] = internet_rules
    for vr in _list(_get(p, "virtualNetworkRules")):
        subnet = _get(_props(vr), "virtualNetworkSubnetId")
        d.add(
            rel(
                subnet,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="virtual network rule",
                network_rule=True,
            )
        )
    pna = _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    if internet_rules:
        d.exposed = True
    elif not fw and _lower(pna) == "enabled":
        # no firewall data (Resource Graph path): a public endpoint is enabled
        d.exposed = True


@extractor("microsoft.sql/servers/databases")
def _x_sql_db(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    sku = d.row.get("sku") or {}
    server = parent_resource_id(d.id)
    d.md.update(
        {
            "role": "database",
            "server_name": server.rsplit("/", 1)[-1] if server else None,
            "server_id": server,
            "resource_group": resource_group_of(d.id).rsplit("/", 1)[-1]
            if resource_group_of(d.id)
            else None,
            "status": _get(p, "status"),
            "edition": _get(sku, "tier") if isinstance(sku, dict) else None,
        }
    )
    d.add(
        rel(_get(p, "elasticPoolId"), EdgeType.CONTAINS, reverse=True, description="elastic pool")
    )


@extractor(
    "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.dbforpostgresql/servers",
    "microsoft.dbformysql/servers",
    "microsoft.dbformariadb/servers",
)
def _x_oss_db(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    fqdn = _get(p, "fullyQualifiedDomainName")
    d.alias(fqdn.lower() if isinstance(fqdn, str) else None)
    net = _get(p, "network") or {}
    d.add(
        rel(
            _get(net, "delegatedSubnetResourceId"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    )
    d.add(rel(_get(net, "privateDnsZoneArmResourceId"), EdgeType.REFERENCES, "DNS_RESOLVED"))
    pna = _get(net, "publicNetworkAccess") or _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    d.md["fqdn"] = fqdn
    if _lower(pna) == "enabled":
        d.exposed = True


@extractor("microsoft.documentdb/databaseaccounts")
def _x_cosmos(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.alias(host_of(_get(p, "documentEndpoint")))
    for vr in _list(_get(p, "virtualNetworkRules")):
        d.add(
            rel(
                _rid(vr),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                network_rule=True,
            )
        )
    _keyvault_key_ref(d, _get(p, "keyVaultKeyUri"))
    ip_rules = [_get(r, "ipAddressOrRange") for r in _list(_get(p, "ipRules"))]
    d.md["ip_rules"] = [r for r in ip_rules if r]
    d.md["vnet_filter"] = _get(p, "isVirtualNetworkFilterEnabled")
    d.md["local_auth_disabled"] = _get(p, "disableLocalAuth")
    pna = _get(p, "publicNetworkAccess")
    d.md["public_network_access"] = pna
    if (
        _lower(pna or "enabled") == "enabled"
        and not _get(p, "isVirtualNetworkFilterEnabled")
        and not d.md["ip_rules"]
    ):
        d.exposed = True


@extractor(
    "microsoft.eventhub/namespaces",
    "microsoft.servicebus/namespaces",
    "microsoft.cognitiveservices/accounts",
    "microsoft.cache/redis",
    "microsoft.search/searchservices",
    "microsoft.appconfiguration/configurationstores",
    "microsoft.eventgrid/topics",
    "microsoft.eventgrid/domains",
    "microsoft.signalrservice/signalr",
    "microsoft.machinelearningservices/workspaces",
    "microsoft.synapse/workspaces",
    "microsoft.datafactory/factories",
)
def _x_paas_endpoint(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    for key in ("serviceBusEndpoint", "endpoint", "hostName", "discoveryUrl"):
        d.alias(host_of(_get(p, key)))
    _keyvault_key_ref(
        d,
        _path(p, "encryption", "keyVaultProperties", "keyVaultUri")
        or _path(p, "encryption", "keyVaultProperties", "keyIdentifier"),
    )
    _network_rule_grants(d, _get(p, "networkAcls") or _get(p, "networkRuleSet"))
    d.add(rel(_get(p, "subnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
    for key in ("keyVault", "storageAccount", "applicationInsights", "containerRegistry"):
        target = _get(p, key)
        if isinstance(target, str) and target.lower().startswith("/subscriptions/"):
            d.add(rel(target, EdgeType.REFERENCES, "DEPENDS_ON", description=key))
    managed_rg = _get(p, "managedResourceGroupName")
    if managed_rg:
        d.add(
            rel(
                f"/subscriptions/{d.account_id}/resourceGroups/{managed_rg}",
                EdgeType.MANAGES,
                "OWNED_BY",
            )
        )
    _set_exposure(d)


@extractor("microsoft.databricks/workspaces")
def _x_databricks(d: _Draft, b: "AzureAssetBuilder") -> None:
    p = d.props
    d.add(
        rel(
            _get(p, "managedResourceGroupId"),
            EdgeType.MANAGES,
            "OWNED_BY",
            description="managed resource group",
        )
    )
    params = _get(p, "parameters") or {}
    vnet = _get(_get(params, "customVirtualNetworkId") or {}, "value")
    d.add(rel(vnet, EdgeType.ATTACHED_TO, description="VNet injection"))
    d.alias(host_of(_get(p, "workspaceUrl")))
    _set_exposure(d)


@extractor("microsoft.operationalinsights/workspaces")
def _x_log_analytics(d: _Draft, b: "AzureAssetBuilder") -> None:
    customer = _get(d.props, "customerId")
    if isinstance(customer, str):
        d.alias(f"{LOG_ANALYTICS_PREFIX}{customer.lower()}")
        d.md["customer_id"] = customer
    d.md["retention_days"] = _get(d.props, "retentionInDays")


@extractor("microsoft.managedidentity/userassignedidentities")
def _x_uami(d: _Draft, b: "AzureAssetBuilder") -> None:
    pid = _get(d.props, "principalId")
    d.md["principal_id"] = pid
    d.md["client_id"] = _get(d.props, "clientId")
    if pid:
        d.alias(principal_ref(pid))
        b.register_principal(pid, d)


@extractor("microsoft.eventgrid/systemtopics")
def _x_system_topic(d: _Draft, b: "AzureAssetBuilder") -> None:
    source = _get(d.props, "source")
    d.md["topic_type"] = _get(d.props, "topicType")
    d.add(rel(source, EdgeType.INVOKES, "TRIGGERED_BY", reverse=True, description="event source"))


@extractor(
    "microsoft.eventgrid/systemtopics/eventsubscriptions",
    "microsoft.eventgrid/topics/eventsubscriptions",
)
def _x_event_subscription(d: _Draft, b: "AzureAssetBuilder") -> None:
    dest = _get(d.props, "destination") or {}
    target = _path(dest, "properties", "resourceId") or host_of(
        _path(dest, "properties", "endpointUrl")
    )
    d.md["endpoint_type"] = _get(dest, "endpointType")
    d.add(rel(target, EdgeType.INVOKES, "INVOKES", description="event delivery"))
    parent = parent_resource_id(d.id)
    if parent and target:
        b.defer(
            parent,
            rel(target, EdgeType.INVOKES, "INVOKES", description=f"event subscription {d.name}"),
        )


@extractor("microsoft.insights/components")
def _x_app_insights(d: _Draft, b: "AzureAssetBuilder") -> None:
    d.md["app_id"] = _get(d.props, "AppId")


@extractor("microsoft.recoveryservices/vaults", "microsoft.dataprotection/backupvaults")
def _x_backup_vault(d: _Draft, b: "AzureAssetBuilder") -> None:
    _set_exposure(d)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class AzureAssetBuilder:
    """Turn ARM-shaped rows into linked CloudAssets for one subscription.

    Args:
        subscription_id: Subscription the rows belong to.
        discovered_via: Collection source recorded in ``metadata["collected_via"]``.
    """

    def __init__(self, subscription_id: str, discovered_via: str = "resource-graph") -> None:
        self.subscription_id = subscription_id
        self.discovered_via = discovered_via
        self._drafts: dict[str, _Draft] = {}
        self._deferred: list[tuple[str, dict[str, Any]]] = []
        self._principal_owner: dict[str, str] = {}
        self._principal_types: dict[str, str | None] = {}
        self._kubelets: dict[str, list[str]] = {}
        self._role_rows: list[dict[str, Any]] = []
        self._extra: list[CloudAsset] = []
        self._subscription_row: dict[str, Any] | None = None
        self._with_subscription = False

    # ── registration hooks used by extractors ──

    def register_principal(self, principal_id: str, draft: _Draft) -> None:
        self._principal_owner.setdefault(principal_id.lower(), draft.id.lower())

    def note_principal(self, principal_id: Any, principal_type: str | None) -> None:
        if isinstance(principal_id, str) and principal_id:
            key = principal_id.lower()
            if principal_type or key not in self._principal_types:
                self._principal_types[key] = principal_type

    def register_kubelet(self, object_id: str, draft: _Draft) -> None:
        self._kubelets.setdefault(object_id.lower(), []).append(draft.id)

    def defer(self, owner_id: str | None, relation: dict[str, Any] | None) -> None:
        """Attach a relation to another (possibly not yet built) asset."""
        if owner_id and relation:
            self._deferred.append((owner_id.lower(), relation))

    # ── input ──

    def add_rows(self, rows: Iterable[dict[str, Any]], discovered_via: str | None = None) -> None:
        for row in rows:
            try:
                self.add_row(row, discovered_via=discovered_via)
            except Exception:
                logger.debug("Skipping Azure row %s", (row or {}).get("id"), exc_info=True)

    def add_row(
        self,
        row: dict[str, Any],
        *,
        synthetic: bool = False,
        discovered_via: str | None = None,
        vnet_id: str | None = None,
    ) -> _Draft | None:
        if not isinstance(row, dict):
            return None
        rid = row.get("id")
        rtype = _lower(row.get("type"))
        if not rid or not rtype:
            return None
        name = row.get("name") or rid.rstrip("/").rsplit("/", 1)[-1]
        if rtype == "microsoft.sql/servers/databases" and str(name).lower() == "master":
            return None
        if rtype == "microsoft.resources/subscriptions":
            self._subscription_row = row
            return None
        key = rid.lower()
        existing = self._drafts.get(key)
        has_props = isinstance(row.get("properties"), dict)
        if existing is not None and (not has_props or existing.props):
            return existing  # first detailed copy wins
        props = row.get("properties") if has_props else {}
        kind = row.get("kind")
        account = row.get("subscriptionId") or subscription_of(rid) or self.subscription_id
        draft = _Draft(
            row=row,
            id=rid,
            type=rtype,
            name=str(name),
            props=dict(props),
            asset_type=asset_type_from_arm(rtype, kind),
            region=row.get("location") or "global",
            account_id=account,
            tags=_tags(row.get("tags")),
            synthetic=synthetic,
        )
        sku = row.get("sku")
        draft.md = {
            "resource_type": row.get("type"),
            "kind": kind,
            "sku": _get(sku, "name") if isinstance(sku, dict) else sku,
            "resource_group": row.get("resourceGroup")
            or (resource_group_of(rid).rsplit("/", 1)[-1] if resource_group_of(rid) else None),
            "collected_via": discovered_via or self.discovered_via,
        }
        if discovered_via == "arm-sweep" or (not has_props and not synthetic):
            draft.md["discovered_via"] = "arm-sweep"
        if row.get("zones"):
            draft.md["zones"] = row.get("zones")
        if row.get("plan"):
            draft.md["plan"] = row.get("plan")
        if vnet_id:
            draft.md["vnet_id"] = vnet_id
        self._drafts[key] = draft
        for fn in _COMMON + _EXTRACTORS.get(rtype, []):
            try:
                fn(draft, self)
            except Exception:
                logger.debug("Azure extractor %s failed for %s", fn.__name__, rid, exc_info=True)
        return draft

    def add_containers(self, rows: Iterable[dict[str, Any]]) -> None:
        """Resource groups (and the subscription row) of ``resourcecontainers``."""
        self._with_subscription = True
        for row in rows:
            rtype = _lower((row or {}).get("type"))
            if rtype == "microsoft.resources/subscriptions":
                self._subscription_row = row
            elif rtype in (
                "microsoft.resources/subscriptions/resourcegroups",
                "microsoft.resources/resourcegroups",
            ):
                row = dict(row)
                row["type"] = "microsoft.resources/subscriptions/resourcegroups"
                self.add_row(row, discovered_via=self.discovered_via)

    def include_subscription(self, row: dict[str, Any] | None = None) -> None:
        self._with_subscription = True
        if row:
            self._subscription_row = row

    def add_role_assignments(self, rows: Iterable[dict[str, Any]]) -> None:
        self._role_rows.extend(r for r in rows if isinstance(r, dict))

    def add_defender_pricings(self, rows: Iterable[dict[str, Any]]) -> None:
        sub_ref = subscription_ref(self.subscription_id)
        for row in rows:
            if not isinstance(row, dict):
                continue
            props = row.get("properties") or {}
            plan = row.get("name") or str(row.get("id", "")).rsplit("/", 1)[-1]
            if not plan:
                continue
            tier = _get(props, "pricingTier")
            enabled = _lower(tier) == "standard"
            service = f"defender-{plan.lower()}"
            md: dict[str, Any] = {
                "security_service": service,
                "enabled": enabled,
                "pricing_tier": tier,
                "sub_plan": _get(props, "subPlan"),
                "resource_type": "microsoft.security/pricings",
                "aliases": [f"azure-security:{service}:{self.subscription_id}"],
            }
            if enabled:
                md["relations"] = [
                    rel(
                        sub_ref,
                        EdgeType.MONITORS,
                        "MONITORED_BY",
                        description=f"Defender for Cloud plan {plan}",
                    )
                ]
            else:
                md["status"] = "not enabled"
            self._extra.append(
                CloudAsset(
                    arn=row.get("id") or f"{sub_ref}/providers/Microsoft.Security/pricings/{plan}",
                    name=f"Defender for Cloud: {plan}" + ("" if enabled else " (not enabled)"),
                    asset_type=AssetType.THREAT_DETECTOR,
                    provider=CloudProvider.AZURE,
                    region="global",
                    account_id=self.subscription_id,
                    metadata=md,
                )
            )

    # ── output ──

    def _role_assignments(self) -> None:
        placeholders: dict[str, CloudAsset] = {}
        registries = [
            d for d in self._drafts.values() if d.type == "microsoft.containerregistry/registries"
        ]
        for ra in self._role_rows:
            props = ra.get("properties") or {}
            pid = ra.get("principalId") or _get(props, "principalId")
            if not pid:
                continue
            ptype = ra.get("principalType") or _get(props, "principalType")
            scope = normalize_scope(ra.get("scope") or _get(props, "scope"))
            rd = ra.get("roleDefinitionId") or _get(props, "roleDefinitionId") or ""
            m = _GUID_TAIL_RE.search(str(rd))
            guid = (ra.get("roleGuid") or (m.group(1) if m else "")).lower()
            role_name = ra.get("roleName") or BUILTIN_ROLES.get(guid) or guid or "unknown role"
            rl = role_name.lower()
            privileged = (
                rl in PRIVILEGED_ROLES or rl.endswith("administrator") or rl.endswith("data owner")
            )
            relation = rel(
                scope,
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                description=f"{role_name} on {scope}",
                role=role_name,
                role_definition_id=rd,
                privileged=privileged,
                principal_type=ptype,
                assignment_id=ra.get("id"),
                condition=_get(props, "condition"),
            )
            self.note_principal(pid, ptype)
            owner = self._principal_owner.get(pid.lower())
            if owner and owner in self._drafts:
                self._drafts[owner].add(relation)
            else:
                ph = placeholders.get(pid.lower()) or self._placeholder(pid, ptype)
                placeholders[pid.lower()] = ph
                if relation:
                    ph.metadata.setdefault("relations", []).append(relation)
            # AKS kubelet identity with AcrPull -> the cluster pulls from the registry
            if guid == ACR_PULL_ROLE_ID and pid.lower() in self._kubelets and scope:
                sl = scope.lower()
                targets = [
                    r.id
                    for r in registries
                    if r.id.lower() == sl or r.id.lower().startswith(sl + "/")
                ]
                if not targets and "/providers/microsoft.containerregistry/registries/" in sl:
                    targets = [scope]
                for aks_id in self._kubelets[pid.lower()]:
                    for reg in targets:
                        self.defer(
                            aks_id,
                            rel(
                                reg,
                                EdgeType.USES_IMAGE,
                                "RUNS_ON",
                                description="kubelet identity has AcrPull",
                                via="AcrPull",
                            ),
                        )
        self._extra.extend(placeholders.values())
        # principals referenced elsewhere (Key Vault policies, SQL admins) without an owner
        for key, ptype in self._principal_types.items():
            if key in placeholders or key in self._principal_owner:
                continue
            self._extra.append(self._placeholder(key, ptype))

    def _placeholder(self, principal_id: str, principal_type: str | None) -> CloudAsset:
        ptl = _lower(principal_type)
        if ptl == "user":
            asset_type = AssetType.IDENTITY_USER
        elif ptl == "group":
            asset_type = AssetType.IDENTITY_GROUP
        else:
            asset_type = AssetType.SERVICE_PRINCIPAL
        label = principal_type or "principal"
        return CloudAsset(
            arn=principal_ref(principal_id),
            name=f"Entra {label} {principal_id.lower()}",
            asset_type=asset_type,
            provider=CloudProvider.AZURE,
            region="global",
            account_id=None,
            metadata={
                "principal_id": principal_id.lower(),
                "principal_type": principal_type or "Unknown",
                "placeholder": True,
                "discovered_via": "entra-principal-reference",
            },
        )

    def _subscription_asset(self) -> CloudAsset:
        row = self._subscription_row or {}
        props = row.get("properties") or {}
        sub = self.subscription_id
        display = (
            row.get("name")
            if row.get("name") and row.get("name") != sub
            else _get(props, "displayName")
        )
        return CloudAsset(
            arn=subscription_ref(sub),
            name=display or f"subscription {sub}",
            asset_type=AssetType.CLOUD_ACCOUNT,
            provider=CloudProvider.AZURE,
            region="global",
            account_id=sub,
            tags=_tags(row.get("tags")),
            metadata={
                "account_id": sub,
                "subscription_id": sub,
                "display_name": display,
                "state": _get(props, "state"),
                "tenant_id": row.get("tenantId"),
                "discovered_via": "azure-subscription",
            },
        )

    def build(self) -> list[CloudAsset]:
        """Finalize: role assignments, deferred relations, then CloudAssets."""
        self._role_assignments()
        for owner, relation in self._deferred:
            draft = self._drafts.get(owner)
            if draft is not None:
                draft.add(relation)
        assets: list[CloudAsset] = []
        if self._with_subscription:
            assets.append(self._subscription_asset())
        for d in self._drafts.values():
            md = dict(d.md)
            md["properties"] = sanitize(d.props)
            rels: list[dict[str, Any]] = []
            seen: set[tuple[Any, ...]] = set()
            for r in d.relations:
                k = (
                    str(r.get("target")).lower(),
                    r.get("edge"),
                    r.get("reverse", False),
                    r.get("relationship"),
                )
                if k not in seen:
                    seen.add(k)
                    rels.append(r)
            if rels:
                md["relations"] = rels
            if d.aliases:
                md["aliases"] = list(dict.fromkeys(d.aliases))
            assets.append(
                CloudAsset(
                    arn=d.id,
                    name=d.name,
                    asset_type=d.asset_type,
                    provider=CloudProvider.AZURE,
                    region=d.region,
                    account_id=d.account_id,
                    tags=d.tags,
                    metadata=md,
                    raw_data={"id": d.id, "type": d.row.get("type")},
                    is_internet_exposed=d.exposed,
                )
            )
        assets.extend(self._extra)
        return assets


def build_assets(
    rows: Iterable[dict[str, Any]],
    subscription_id: str,
    discovered_via: str = "resource-graph",
) -> list[CloudAsset]:
    """Convenience: rows of one subscription -> linked CloudAssets."""
    builder = AzureAssetBuilder(subscription_id, discovered_via)
    builder.add_rows(rows)
    return builder.build()


def collect_subscription_graph(
    client: Any,
    subscription_id: str,
    *,
    role_assignments: bool = True,
    defender: bool = True,
    errors: dict[str, str] | None = None,
) -> AzureAssetBuilder:
    """Query ARG for one subscription and return a populated builder.

    The ``resources`` query must succeed (its exception propagates so the
    caller can fall back to the SDK path); the container, role-assignment
    and Defender queries are best-effort and record failures in ``errors``.
    """
    errors = errors if errors is not None else {}
    subs = [subscription_id]
    builder = AzureAssetBuilder(subscription_id, "resource-graph")
    resource_rows = run_query(client, resources_query(subscription_id), subscriptions=subs)
    builder.add_rows(resource_rows)
    builder.include_subscription()
    try:
        builder.add_containers(
            run_query(client, containers_query(subscription_id), subscriptions=subs)
        )
    except Exception as exc:
        errors["resource_graph_containers"] = str(exc)
    if role_assignments:
        try:
            builder.add_role_assignments(
                run_query(client, role_assignments_query(subscription_id), subscriptions=subs)
            )
        except Exception as exc:
            errors["resource_graph_role_assignments"] = str(exc)
    if defender:
        try:
            builder.add_defender_pricings(
                run_query(client, defender_query(subscription_id), subscriptions=subs)
            )
        except Exception as exc:
            errors["resource_graph_defender"] = str(exc)
    return builder
