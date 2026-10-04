"""Drafts, the extractor registry and the extractors every row goes through."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.helpers import (
    _get,
    _list,
    _lower,
    _path,
    _props,
    _rid,
    host_of,
    parent_resource_id,
    principal_ref,
    resource_group_of,
    subscription_of,
    subscription_ref,
)
from cloudg.schema.models import AssetType, EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.azure_graph.builder import AzureAssetBuilder


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


def _network_rule_grant(target: Any, description: str | None = None) -> dict[str, Any] | None:
    """Reverse GRANTS_ACCESS from a network ACL entry (subnet / resource instance)."""
    return rel(
        target,
        EdgeType.GRANTS_ACCESS,
        "POLICY_ALLOWS_ACTION",
        reverse=True,
        description=description,
        network_rule=True,
    )


def _network_rule_grants(d: _Draft, acls: Any) -> None:
    if not isinstance(acls, dict):
        return
    for vr in _list(_get(acls, "virtualNetworkRules")):
        subnet = _rid(vr) or _get(vr, "virtualNetworkResourceId")
        d.add(_network_rule_grant(subnet, "virtual network rule"))
    for rr in _list(_get(acls, "resourceAccessRules")):
        d.add(_network_rule_grant(_get(rr, "resourceId"), "resource instance rule"))
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
