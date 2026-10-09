"""Cross-service relationship linker.

Derives the edges that interlink an inventory — attachment, containment,
routing, invocation, identity, protection, monitoring, governance and
generic references — purely from collected asset metadata. No cloud API
calls and no scanners: given any list of CloudAssets (AWS, Azure, GCP, or
mixed), it produces the edges that turn a flat inventory into a connected
map.

Three passes:

1. Declared relations: collectors record what an asset talks to in
   ``metadata["relations"]`` (target identifier, edge type, ontology
   relationship, direction, properties). The linker resolves each target
   and emits a typed edge.
2. Provider-aware rules: security-group attachment, subnet containment,
   route-table routes, ENI/volume attachment, VPC peering, Lambda VPC
   config, execution roles, CloudFront origins and WAF, KMS references,
   Azure NIC wiring, GCP parent containment.
3. Generic reference scan: any identifier string found inside an asset's
   metadata that resolves to another collected asset becomes a REFERENCES
   edge. This catches cross-service links no explicit rule knows about.

Identifier resolution is scope-aware: ambiguous identifiers (names such as
``default``) resolve to the candidate in the same account and region,
then the same account, and are left unresolved rather than guessed when
several accounts share them. References to resources in accounts that
were not collected become ``CLOUD_ACCOUNT`` placeholder nodes marked
``external``, so cross-account dependencies stay visible.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from cloudg.inventory._util import walk_strings

# Identifier index / resolution live in linker_index; the helpers below are
# re-exported so existing imports from this module keep working.
from cloudg.inventory.linker_index import (
    _ECR_HOST_RE,
    _GLOBAL_PREFIXES,
    _NO_TAIL_PREFIXES,
    IdentifierIndex,
    _image_registry_host,
)
from cloudg.inventory.linker_rules import RuleLinksMixin
from cloudg.schema.models import AssetType, CloudAsset, EdgeType, NetworkEdge

logger = logging.getLogger(__name__)

# AWS-native short-ID shapes worth indexing (i-, vpc-, subnet-, sg-, ...)
_AWS_ID_RE = re.compile(
    r"^(i|vpc|subnet|sg|vol|eni|igw|eigw|nat|rtb|acl|pcx|tgw|tgw-attach|tgw-rtb|eipalloc|lt|vpce|vpce-svc|fs|fsap|fl|pl|vgw|cgw|vpn|snap|ami)-[0-9a-f]{8,17}$"
)
_SSO_ROLE_HASH_RE = re.compile(r"[0-9a-f]{16}")

# GCP full resource names, anchored so ".googleapis.com" cannot match mid-string
_GCP_NAME_RE = re.compile(r"^//[a-z0-9-]+\.googleapis\.com/")

# Metadata keys whose values identify the asset itself (never link targets)
_SELF_ID_KEYS = {
    "group_id",
    "subnet_id_self",
    "route_table_id",
    "internet_gateway_id",
    "nat_gateway_id",
    "network_interface_id",
    "volume_id",
    "allocation_id",
    "network_acl_id",
    "peering_connection_id",
    "transit_gateway_id",
    "policy_id",
    "vpc_endpoint_id",
    "launch_template_id",
    "file_system_id",
    "flow_log_id",
    "cluster_arn",
}

# Metadata keys the generic pass never scans (already linked explicitly)
_SKIP_GENERIC_KEYS = {"relations", "aliases", "assume_role_policy"}

_MAX_SCAN_DEPTH = 6
_MAX_UNRESOLVED = 2000


class RelationshipLinker(RuleLinksMixin, IdentifierIndex):
    """Builds interconnection edges between already-collected assets.

    Args:
        assets: The inventory to link.
        materialize_external: Create placeholder account nodes for
            references into accounts that were not collected.
    """

    def __init__(self, assets: list[CloudAsset], materialize_external: bool = True) -> None:
        super().__init__(assets)  # builds the identifier index
        self._edge_keys: set[tuple[str, str, str]] = set()
        self._pair_keys: set[tuple[str, str]] = set()
        self._materialize_external = materialize_external
        self.external_assets: list[CloudAsset] = []
        self._external_ids: set[str] = set()
        self.unresolved: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # External placeholders and bookkeeping
    # ------------------------------------------------------------------

    def _external_account(self, identifier: str, context: CloudAsset) -> str | None:
        """Account node (AWS account, Azure subscription, GCP project) for an
        identifier living in an account we did not map."""
        if not self._materialize_external or not isinstance(identifier, str):
            return None
        found = self._foreign_account(identifier)
        if found is None:
            return None
        provider, acct, ref = found
        if acct == "aws" or acct.lower() == (context.account_id or "").lower():
            return None
        existing = self._index.get(ref) or self._index.get(ref.lower())
        if existing:
            return existing[0]
        placeholder = CloudAsset(
            arn=ref,
            name=f"external account {acct}",
            asset_type=AssetType.CLOUD_ACCOUNT,
            provider=provider,
            region="global",
            account_id=acct,
            metadata={
                "account_id": acct,
                "external": True,
                "discovered_via": "cross-account reference",
            },
        )
        self.external_assets.append(placeholder)
        self._external_ids.add(placeholder.id)
        self._by_id[placeholder.id] = placeholder
        self._index_asset(placeholder)
        return placeholder.id

    def _note_unresolved(self, asset: CloudAsset, target: str, edge: str) -> None:
        if len(self.unresolved) < _MAX_UNRESOLVED:
            self.unresolved.append(
                {
                    "source": asset.arn or asset.id,
                    "source_name": asset.name,
                    "target": target,
                    "edge_type": edge,
                }
            )

    # ------------------------------------------------------------------
    # Edge helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        edges: list[NetworkEdge],
        source_id: str | None,
        target_id: str | None,
        edge_type: EdgeType,
        description: str | None = None,
        relationship: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> None:
        if not source_id or not target_id or source_id == target_id:
            return
        key = (source_id, target_id, edge_type.value)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self._pair_keys.add((source_id, target_id))
        edges.append(
            NetworkEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                description=description,
                relationship=relationship,
                properties=properties or {},
            )
        )

    # ------------------------------------------------------------------
    # Pass 1: declared relations
    # ------------------------------------------------------------------

    def _link_declared(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        for r in asset.metadata.get("relations", []) or []:
            if not isinstance(r, dict):
                continue
            target_ref = r.get("target")
            try:
                edge_type = EdgeType(r.get("edge", EdgeType.REFERENCES.value))
            except ValueError:
                edge_type = EdgeType.REFERENCES
            target = self.resolve(target_ref, asset)
            if target is None and isinstance(target_ref, str):
                target = self._external_account(target_ref, asset)
            if target is None:
                self._note_unresolved(asset, str(target_ref), edge_type.value)
                continue
            src, dst = (target, asset.id) if r.get("reverse") else (asset.id, target)
            props = dict(r.get("properties") or {})
            if target in self._external_ids and target_ref:
                props.setdefault("external_reference", target_ref)
            self._add(
                edges,
                src,
                dst,
                edge_type,
                r.get("description"),
                r.get("relationship"),
                props,
            )

    # ------------------------------------------------------------------
    # Pass 2: provider-aware rules (_link_rules, from RuleLinksMixin) and
    # Identity Center permission sets
    # ------------------------------------------------------------------

    def _link_sso_roles(self, edges: list[NetworkEdge]) -> None:
        """Identity Center permission set -> the AWSReservedSSO_<name>_<hash>
        role it provisions in every assigned account."""
        sets = [a for a in self._assets if a.metadata.get("provisioned_role_prefix")]
        if not sets:
            return
        roles = [
            a
            for a in self._assets
            if a.asset_type == AssetType.IAM_ROLE
            and str(a.metadata.get("path") or "").startswith("/aws-reserved/sso.amazonaws.com/")
        ]
        for ps in sets:
            prefix = ps.metadata["provisioned_role_prefix"]
            for role in roles:
                if role.name.startswith(prefix) and _SSO_ROLE_HASH_RE.fullmatch(
                    role.name[len(prefix) :]
                ):
                    self._add(
                        edges,
                        ps.id,
                        role.id,
                        EdgeType.MANAGES,
                        f"{ps.name} provisions {role.name}",
                        "OWNED_BY",
                    )

    # ------------------------------------------------------------------
    # Pass 3: generic reference scan
    # ------------------------------------------------------------------

    def _iter_strings(self, value: Any) -> Iterable[str]:
        return walk_strings(value, _MAX_SCAN_DEPTH)

    def _looks_like_identifier(self, value: str) -> bool:
        if value.startswith("arn:") or value.startswith("/subscriptions/"):
            return True
        if _GCP_NAME_RE.match(value):
            return True
        return bool(_AWS_ID_RE.match(value))

    def _link_generic(self, asset: CloudAsset, edges: list[NetworkEdge]) -> None:
        own_ids = {asset.arn, asset.name}
        md = {k: v for k, v in asset.metadata.items() if k not in _SKIP_GENERIC_KEYS}
        for key in _SELF_ID_KEYS:
            own_ids.add(md.pop(key, None))
        for value in self._iter_strings(md):
            if value in own_ids or not self._looks_like_identifier(value):
                continue
            target = self.resolve(value, asset)
            if not target or target == asset.id:
                continue
            if self._linked_either_way(asset.id, target):
                continue
            description = f"{asset.name} references {value}"
            self._add(edges, asset.id, target, EdgeType.REFERENCES, description)

    # ------------------------------------------------------------------
    # Main interface
    # ------------------------------------------------------------------

    def link(self, include_generic: bool = True) -> list[NetworkEdge]:
        """Run all linking passes and return deduplicated edges.

        External account placeholders created along the way are available
        on :attr:`external_assets`; unresolvable declared references on
        :attr:`unresolved`.

        Args:
            include_generic: Also run the generic reference scan (pass 3).
        """
        edges: list[NetworkEdge] = []
        for asset in self._assets:
            try:
                self._link_declared(asset, edges)
            except Exception:
                logger.debug("Declared linking failed for %s", asset.name, exc_info=True)
        for asset in self._assets:
            try:
                self._link_rules(asset, edges)
            except Exception:
                logger.debug("Rule linking failed for %s", asset.name, exc_info=True)
        try:
            self._link_sso_roles(edges)
        except Exception:
            logger.debug("SSO role linking failed", exc_info=True)
        if include_generic:
            for asset in self._assets:
                try:
                    self._link_generic(asset, edges)
                except Exception:
                    logger.debug("Generic linking failed for %s", asset.name, exc_info=True)
        logger.info(
            "Linker derived %d relationship edges (%d external accounts, %d unresolved references)",
            len(edges),
            len(self.external_assets),
            len(self.unresolved),
        )
        return edges

    def seed_existing(self, edges: list[NetworkEdge]) -> None:
        """Register already-collected edges so the linker won't duplicate them."""
        for edge in edges:
            self._edge_keys.add((edge.source_id, edge.target_id, edge.edge_type.value))
            self._pair_keys.add((edge.source_id, edge.target_id))


# Public API, including names re-exported from the split-out modules
__all__ = [
    "IdentifierIndex",
    "RelationshipLinker",
    "_ECR_HOST_RE",
    "_GLOBAL_PREFIXES",
    "_image_registry_host",
    "_NO_TAIL_PREFIXES",
]
