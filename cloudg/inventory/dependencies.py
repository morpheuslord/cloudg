"""Interdependency analysis over a linked inventory.

Edges in the inventory map point in their natural direction ("lambda
ASSUMES_ROLE role", "bucket INVOKES lambda", "WAF PROTECTS ALB"). For
dependency questions every edge is turned into a single
``dependent -> dependency`` arrow with :data:`DEPENDENCY_DIRECTION`:

- ``forward``: the source depends on the target (a function depends on
  its role, image, KMS key, log group; a route table on its gateway; a
  principal on the role it assumes and the resources it is granted).
- ``reverse``: the target depends on the source (a subnet's instances on
  the subnet, a function on the queue that triggers it, an ALB on the WAF
  protecting it, a resource on the stack managing it, an account on the
  SCPs governing it).

On that graph:

- ``depends_on(x)`` is everything ``x`` needs (upstream).
- ``dependents(x)`` is everything that needs ``x`` (downstream): its blast
  radius if ``x`` breaks, is deleted or is changed.

This is an availability / change-impact view. Compromise propagation runs
the other way along identity edges (a compromised function exposes its
role) and is better answered from the IAM_TRUST / ASSUMES_ROLE /
GRANTS_ACCESS edges directly.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from cloudg.schema.models import AssetType, CloudAsset, EdgeType, NetworkEdge

DEPENDENCY_DIRECTION: dict[str, str] = {
    EdgeType.REFERENCES.value: "forward",
    EdgeType.ATTACHED_TO.value: "forward",
    EdgeType.ROUTE.value: "forward",
    EdgeType.PEERING.value: "forward",
    EdgeType.USES_IMAGE.value: "forward",
    EdgeType.ASSUMES_ROLE.value: "forward",
    EdgeType.LOGS_TO.value: "forward",
    EdgeType.LOAD_BALANCER_TARGET.value: "forward",
    EdgeType.GRANTS_ACCESS.value: "forward",
    EdgeType.IAM_POLICY_ATTACHMENT.value: "forward",
    EdgeType.IAM_TRUST.value: "forward",
    EdgeType.CONTAINS.value: "reverse",
    EdgeType.INVOKES.value: "reverse",
    EdgeType.PROTECTS.value: "reverse",
    EdgeType.MONITORS.value: "reverse",
    EdgeType.MANAGES.value: "reverse",
    EdgeType.GOVERNS.value: "reverse",
}

# Hierarchy edges (org -> OU -> account -> resource) answer "where", not
# "what breaks": excluded from blast radius unless explicitly requested.
_HIERARCHY_TYPES = {AssetType.ORGANIZATION, AssetType.ORG_UNIT, AssetType.CLOUD_ACCOUNT}

# Shared-dependency ranking ignores pure containers and placement
_STRUCTURAL_EDGES = {EdgeType.CONTAINS.value, EdgeType.PEERING.value}


@dataclass
class DependencyLink:
    """One hop in a dependency walk."""

    asset_id: str
    via_edge: str
    relationship: str | None
    depth: int
    parent_id: str


class DependencyGraph:
    """Directed ``dependent -> dependency`` view of an inventory."""

    def __init__(
        self,
        assets: list[CloudAsset],
        edges: list[NetworkEdge],
        include_hierarchy: bool = False,
    ) -> None:
        self.assets = {a.id: a for a in assets}
        self._needs: dict[str, list[tuple[str, NetworkEdge]]] = {}
        self._needed_by: dict[str, list[tuple[str, NetworkEdge]]] = {}
        for e in edges:
            direction = DEPENDENCY_DIRECTION.get(e.edge_type.value)
            if direction is None or e.source_id not in self.assets or e.target_id not in self.assets:
                continue
            dependent, dependency = (
                (e.source_id, e.target_id) if direction == "forward" else (e.target_id, e.source_id)
            )
            if not include_hierarchy and (
                self.assets[dependency].asset_type in _HIERARCHY_TYPES
                and e.edge_type == EdgeType.CONTAINS
            ):
                continue
            self._needs.setdefault(dependent, []).append((dependency, e))
            self._needed_by.setdefault(dependency, []).append((dependent, e))

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def find(self, ref: str) -> CloudAsset | None:
        """Find an asset by internal ID, ARN / resource ID, or unique name."""
        if ref in self.assets:
            return self.assets[ref]
        by_arn = [a for a in self.assets.values() if a.arn == ref]
        if by_arn:
            return by_arn[0]
        by_name = [a for a in self.assets.values() if a.name == ref]
        if len(by_name) == 1:
            return by_name[0]
        tail = [a for a in self.assets.values() if a.arn and a.arn.rsplit("/", 1)[-1] == ref]
        return tail[0] if len(tail) == 1 else None

    # ------------------------------------------------------------------
    # Walks
    # ------------------------------------------------------------------

    def _walk(
        self, start: str, adjacency: dict[str, list[tuple[str, NetworkEdge]]], max_depth: int
    ) -> list[DependencyLink]:
        seen = {start}
        out: list[DependencyLink] = []
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for nxt, edge in adjacency.get(node, []):
                if nxt in seen:
                    continue
                seen.add(nxt)
                out.append(DependencyLink(nxt, edge.edge_type.value, edge.relationship, depth + 1, node))
                queue.append((nxt, depth + 1))
        return out

    def depends_on(self, asset_id: str, max_depth: int = 10) -> list[DependencyLink]:
        """Everything ``asset_id`` needs, breadth-first."""
        return self._walk(asset_id, self._needs, max_depth)

    def dependents(self, asset_id: str, max_depth: int = 10) -> list[DependencyLink]:
        """Everything that needs ``asset_id``: its blast radius."""
        return self._walk(asset_id, self._needed_by, max_depth)

    def direct_counts(self, asset_id: str) -> tuple[int, int]:
        return len(self._needs.get(asset_id, [])), len(self._needed_by.get(asset_id, []))

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def _describe(self, asset_id: str) -> dict[str, Any]:
        a = self.assets[asset_id]
        return {
            "id": a.id,
            "name": a.name,
            "arn": a.arn,
            "type": a.asset_type.value,
            "account_id": a.account_id,
            "region": a.region,
        }

    def tree(self, asset_id: str, direction: str = "both", max_depth: int = 3) -> dict[str, Any]:
        """Nested upstream/downstream view for one asset."""

        def nest(links: list[DependencyLink]) -> list[dict[str, Any]]:
            children: dict[str, list[DependencyLink]] = {}
            for link in links:
                children.setdefault(link.parent_id, []).append(link)

            def build(parent: str) -> list[dict[str, Any]]:
                return [
                    {
                        **self._describe(link.asset_id),
                        "via": link.via_edge,
                        "relationship": link.relationship,
                        "children": build(link.asset_id),
                    }
                    for link in children.get(parent, [])
                ]

            return build(asset_id)

        out: dict[str, Any] = {"asset": self._describe(asset_id)}
        if direction in ("up", "both"):
            out["depends_on"] = nest(self.depends_on(asset_id, max_depth))
        if direction in ("down", "both"):
            out["dependents"] = nest(self.dependents(asset_id, max_depth))
        return out

    def shared_dependencies(self, top: int = 25) -> list[dict[str, Any]]:
        """Assets the most other assets directly depend on (excluding pure
        containment), e.g. one KMS key behind forty resources."""
        ranked = []
        for dep_id, users in self._needed_by.items():
            functional = [u for u, e in users if e.edge_type.value not in _STRUCTURAL_EDGES]
            if len(functional) < 2:
                continue
            ranked.append((len(set(functional)), dep_id))
        ranked.sort(reverse=True)
        return [{**self._describe(d), "direct_dependents": n} for n, d in ranked[:top]]

    def blast_radius(self, candidates: Iterable[str] | None = None, top: int = 25) -> list[dict[str, Any]]:
        """Largest transitive dependent sets among ``candidates`` (default:
        the 4x``top`` assets with the most direct dependents)."""
        if candidates is None:
            pool = sorted(self._needed_by, key=lambda n: -len(self._needed_by[n]))[: top * 4]
        else:
            pool = list(candidates)
        scored = []
        for node in pool:
            deps = self.dependents(node)
            accounts = {self.assets[d.asset_id].account_id for d in deps}
            exposed = sum(1 for d in deps if self.assets[d.asset_id].is_internet_exposed)
            scored.append((len(deps), node, len(accounts - {None}), exposed))
        scored.sort(reverse=True)
        return [
            {**self._describe(n), "transitive_dependents": count, "accounts_affected": accts,
             "internet_exposed_dependents": exposed}
            for count, n, accts, exposed in scored[:top]
            if count
        ]


def cross_account_edges(assets: list[CloudAsset], edges: list[NetworkEdge]) -> list[dict[str, Any]]:
    """Edges whose endpoints live in different accounts."""
    by_id = {a.id: a for a in assets}
    out = []
    for e in edges:
        s, t = by_id.get(e.source_id), by_id.get(e.target_id)
        if not s or not t or not s.account_id or not t.account_id or s.account_id == t.account_id:
            continue
        if s.asset_type in _HIERARCHY_TYPES and t.asset_type in _HIERARCHY_TYPES and e.edge_type == EdgeType.CONTAINS:
            continue
        out.append(
            {
                "source": s.arn or s.id,
                "source_account": s.account_id,
                "target": t.arn or t.id,
                "target_account": t.account_id,
                "edge_type": e.edge_type.value,
                "relationship": e.relationship,
                "external": bool(t.metadata.get("external") or s.metadata.get("external")),
            }
        )
    return out


def security_coverage(assets: list[CloudAsset], edges: list[NetworkEdge]) -> dict[str, Any]:
    """Which security services run where, and which workloads no scanner covers."""
    matrix: dict[str, dict[str, dict[str, bool]]] = {}
    for a in assets:
        svc = a.metadata.get("security_service")
        if not svc:
            continue
        acct = a.account_id or "unknown"
        cell = matrix.setdefault(acct, {}).setdefault(a.region, {})
        cell[svc] = cell.get(svc, False) or bool(a.metadata.get("enabled"))

    scanners = {
        a.id for a in assets if a.asset_type == AssetType.VULNERABILITY_SCANNER and a.metadata.get("enabled")
    }
    scanned = {e.target_id for e in edges if e.edge_type == EdgeType.MONITORS and e.source_id in scanners}
    scannable = (AssetType.EC2, AssetType.CONTAINER_REGISTRY, AssetType.LAMBDA_FUNCTION)
    unscanned = [
        {"name": a.name, "arn": a.arn, "type": a.asset_type.value, "account_id": a.account_id, "region": a.region}
        for a in assets
        if a.asset_type in scannable and a.id not in scanned
    ]
    protectable = (AssetType.LOAD_BALANCER, AssetType.API_GATEWAY, AssetType.CLOUDFRONT)
    protected = {e.target_id for e in edges if e.edge_type == EdgeType.PROTECTS}
    unprotected = [
        {"name": a.name, "arn": a.arn, "type": a.asset_type.value, "account_id": a.account_id}
        for a in assets
        if a.asset_type in protectable and a.is_internet_exposed and a.id not in protected
    ]
    gaps = sorted(
        f"{acct}/{region}: {svc}"
        for acct, regions in matrix.items()
        for region, services in regions.items()
        for svc, on in services.items()
        if not on
    )
    return {
        "services_by_account_region": matrix,
        "gaps": gaps,
        "workloads_without_vulnerability_scanning": unscanned,
        "internet_facing_without_waf": unprotected,
    }
