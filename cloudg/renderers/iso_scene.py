"""The 3D scene behind the report's isometric map.

The report draws the estate as a bench of machined parts: one base plate per
provider, a raised platform per account and region, a slab per network, a
tile per subnet and a small solid per asset. Identity and governance assets
sit on a control deck held above the plate on posts, so height means
something: the network plane at the bottom, the control plane above it, and
finding beacons above the assets they affect.

Everything that needs care is decided here, in world units, so it can be
tested without a browser: the packing, the height of every part and the
route of every trace line. The page only projects the scene for the chosen
camera, paints it back to front and animates it.

Trace lines are routed orthogonally in 3D. Each one leaves its source from
its own port on the asset's top face, rises to its own lane, runs along x and
then y (or y and then x) and drops onto its own port on the target. Lanes are
assigned so that no two horizontal runs share a line in space, and no two
lines share a port, which is what keeps every trace followable from end to
end however dense the map gets.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from cloudg.schema.models import CloudAsset, NetworkEdge, ScanResult, Severity

__all__ = ["MAX_SCENE_ASSETS", "build_scene", "category_of", "edge_family"]

#: Above this many assets the page offers the 2D map instead of drawing 3D
MAX_SCENE_ASSETS = 2500

CELL = 18.0  # one asset's square on a tile
TILE_PAD = 5.0  # inset of a tile's contents from its edge
GAP = 8.0  # between sibling containers
BASE_H = 6.0  # provider base plate
REGION_H = 4.0
NETWORK_H = 3.0
SUBNET_H = 2.0
DECK_H = 3.0
LANE_STEP = 2.0  # vertical distance between two trace lanes
LANE_CLEAR = 8.0  # first lane above the taller end of a trace
PORT_STEP = 2.2

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_NETWORK_TYPES = {"VPC", "VNET"}
_SUBNET_TYPES = {"SUBNET"}

# Asset category: (shape the page draws, footprint w, d, height, plane)
# plane is "ground" (on the region platforms) or "deck" (the control deck)
_SHAPES: dict[str, tuple[str, float, float, float, str]] = {
    "compute": ("server", 11, 11, 10, "ground"),
    "cluster": ("cluster", 13, 13, 8, "ground"),
    "function": ("function", 7, 7, 13, "ground"),
    "database": ("database", 11, 11, 11, "ground"),
    "storage": ("bucket", 11, 11, 8, "ground"),
    "messaging": ("queue", 13, 7, 5, "ground"),
    "network": ("gateway", 13, 9, 4, "ground"),
    "security": ("shield", 11, 11, 6, "ground"),
    "secret": ("key", 8, 8, 6, "ground"),
    "observability": ("log", 11, 9, 7, "ground"),
    "ml": ("core", 11, 11, 9, "ground"),
    "identity": ("principal", 7, 7, 10, "deck"),
    "governance": ("plate", 12, 12, 3, "deck"),
    "other": ("box", 9, 9, 6, "ground"),
}

# First keyword that appears in the AssetType value decides the category
_CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "governance",
        (
            "ORGANIZATION",
            "ORG_UNIT",
            "CLOUD_ACCOUNT",
            "ORG_POLICY",
            "LANDING_ZONE",
            "GUARDRAIL",
            "RESOURCE_GROUP",
            "RESOURCE_SHARE",
            "STACK_SET",
            "IAC_STACK",
            "PROVISIONED_PRODUCT",
            "PRODUCT_PORTFOLIO",
            "CONFIG_RECORDER",
        ),
    ),
    (
        "identity",
        (
            "IAM_",
            "SERVICE_PRINCIPAL",
            "IDENTITY_",
            "PERMISSION_SET",
            "ACCESS_KEY",
            "USER_POOL",
            "INSTANCE_PROFILE",
            "K8S_SERVICE_ACCOUNT",
            "AUTHORIZER",
        ),
    ),
    ("secret", ("KMS_KEY", "SECRET", "CERTIFICATE", "KEY_VAULT", "PARAMETER")),
    (
        "security",
        (
            "WAF",
            "FIREWALL",
            "DDOS",
            "THREAT",
            "SECURITY_HUB",
            "SCANNER",
            "ACCESS_ANALYZER",
            "SECURITY_GROUP",
            "NSG",
            "NACL",
            "AI_GUARDRAIL",
        ),
    ),
    ("ml", ("ML_", "AI_AGENT", "KNOWLEDGE_BASE")),
    ("function", ("LAMBDA", "FUNCTION", "EDGE_FUNCTION", "STATE_MACHINE", "RUNBOOK")),
    (
        "cluster",
        (
            "CLUSTER",
            "CONTAINER_SERVICE",
            "NODE_GROUP",
            "FARGATE",
            "K8S_",
            "AUTOSCALING",
            "BATCH",
            "JOB_",
            "APP_SERVICE",
            "TASK_DEFINITION",
            "CAPACITY_PROVIDER",
        ),
    ),
    ("compute", ("EC2", "VIRTUAL_MACHINE", "GCE_INSTANCE", "LAUNCH_TEMPLATE", "MACHINE_IMAGE")),
    (
        "database",
        (
            "RDS",
            "AURORA",
            "SQL",
            "DYNAMODB",
            "CACHE",
            "SEARCH_DOMAIN",
            "DATA_WAREHOUSE",
            "DATABASE",
            "DATA_CATALOG",
            "QUERY_WORKGROUP",
            "ETL_JOB",
            "BIG_DATA",
        ),
    ),
    (
        "storage",
        (
            "BUCKET",
            "BLOB",
            "EBS",
            "VOLUME",
            "FILE_SYSTEM",
            "SNAPSHOT",
            "BACKUP",
            "CONTAINER_REGISTRY",
            "ACCESS_POINT",
            "DATA_TRANSFER",
        ),
    ),
    (
        "messaging",
        (
            "QUEUE",
            "TOPIC",
            "EVENT_",
            "DATA_STREAM",
            "DELIVERY_STREAM",
            "MESSAGE_BROKER",
            "SCHEDULE",
            "API_DESTINATION",
        ),
    ),
    (
        "observability",
        ("LOG", "TRAIL", "FLOW_LOG", "ALARM", "MONITOR", "CI_PIPELINE", "BUILD_", "DEPLOYMENT"),
    ),
    (
        "network",
        (
            "VPC",
            "VNET",
            "SUBNET",
            "ROUTE",
            "GATEWAY",
            "LOAD_BALANCER",
            "TARGET_GROUP",
            "LB_",
            "CLOUDFRONT",
            "CDN",
            "PEERING",
            "ELASTIC_IP",
            "NETWORK_INTERFACE",
            "ENDPOINT",
            "DNS",
            "VPN",
            "DIRECT_CONNECT",
            "ROUTER",
            "PREFIX_LIST",
            "VPC_LINK",
            "CUSTOM_DOMAIN",
            "ACCELERATOR",
            "SERVICE_NETWORK",
            "SERVICE_REGISTRY",
            "API_GATEWAY",
        ),
    ),
]

# Edge families: what kind of path a trace is, which decides its colour key
_EDGE_FAMILIES: dict[str, str] = {
    "INTERNET_EXPOSED": "exposure",
    "SECURITY_GROUP_RULE": "network",
    "NACL_RULE": "network",
    "ROUTE": "network",
    "PEERING": "network",
    "LOAD_BALANCER_TARGET": "network",
    "ATTACHED_TO": "network",
    "IAM_TRUST": "identity",
    "IAM_POLICY_ATTACHMENT": "identity",
    "ASSUMES_ROLE": "identity",
    "GRANTS_ACCESS": "identity",
    "INVOKES": "data",
    "USES_IMAGE": "data",
    "LOGS_TO": "data",
    "REFERENCES": "data",
    "GOVERNS": "governance",
    "MANAGES": "governance",
    "PROTECTS": "governance",
    "MONITORS": "governance",
}

# Lanes start higher for families drawn over others, so they read as layers
_FAMILY_LIFT = {"network": 0.0, "data": 3.0, "identity": 6.0, "governance": 9.0, "exposure": 1.5}


def category_of(asset_type: str) -> str:
    """The drawing category of an AssetType value (``"compute"``, ``"identity"``, ...)."""
    value = asset_type.upper()
    for category, needles in _CATEGORY_RULES:
        if any(needle in value for needle in needles):
            return category
    return "other"


def edge_family(edge_type: str, relationship: str | None = None) -> str:
    """The trace family of an edge: network, identity, data, governance or exposure."""
    if relationship == "INTERNET_REACHABLE":
        return "exposure"
    return _EDGE_FAMILIES.get(edge_type.upper(), "data")


# ---------------------------------------------------------------------------
# Containers and packing
# ---------------------------------------------------------------------------


@dataclass
class _Box:
    """A container or an asset being packed: its size, then its position."""

    key: str
    kind: str  # provider | region | network | subnet | zone | deck | asset
    label: str
    w: float = 0.0
    d: float = 0.0
    x: float = 0.0
    y: float = 0.0
    children: list[_Box] = field(default_factory=list)
    asset: CloudAsset | None = None
    meta: dict[str, Any] = field(default_factory=dict)


def _grid(items: list[_Box]) -> tuple[float, float]:
    """Lay assets in a square-ish grid of cells; returns the inner size."""
    cols = max(1, math.ceil(math.sqrt(len(items))))
    for index, item in enumerate(items):
        item.x = (index % cols) * CELL
        item.y = (index // cols) * CELL
        item.w = item.d = CELL
    rows = math.ceil(len(items) / cols) if items else 0
    return cols * CELL, rows * CELL


def _shelf(children: list[_Box], *, aspect: float = 1.6) -> tuple[float, float]:
    """Shelf-pack sized children, tallest first; returns the inner size."""
    if not children:
        return 0.0, 0.0
    ordered = sorted(children, key=lambda c: (-c.d, -c.w, c.key))
    area = sum((c.w + GAP) * (c.d + GAP) for c in ordered)
    limit = max(max(c.w for c in ordered), math.sqrt(area * aspect))
    x = y = row_d = width = 0.0
    for child in ordered:
        if x > 0 and x + child.w > limit:
            y += row_d + GAP
            x = row_d = 0.0
        child.x, child.y = x, y
        x += child.w + GAP
        row_d = max(row_d, child.d)
        width = max(width, x - GAP)
    return width, y + row_d


def _size(box: _Box) -> None:
    """Size a container from its children (depth first), positions relative."""
    assets = [c for c in box.children if c.kind == "asset"]
    containers = [c for c in box.children if c.kind != "asset"]
    for child in containers:
        _size(child)
    if assets and containers:
        # Loose assets of a container get a zone of their own beside the children
        zone = _Box(f"{box.key}/zone", "zone", f"{box.label} services", children=assets)
        _size(zone)
        containers.append(zone)
        box.children = containers
        assets = []
    if assets:
        inner_w, inner_d = _grid(assets)
    else:
        inner_w, inner_d = _shelf(containers)
    pad = TILE_PAD if box.kind in ("subnet", "zone", "deck") else GAP
    box.w = max(inner_w + pad * 2, CELL + pad * 2)
    box.d = max(inner_d + pad * 2, CELL + pad * 2)
    box.meta["pad"] = pad


def _place(box: _Box, ox: float, oy: float) -> None:
    """Turn relative positions into world positions."""
    box.x += ox
    box.y += oy
    pad = box.meta.get("pad", 0.0)
    for child in box.children:
        _place(child, box.x + pad, box.y + pad)


# ---------------------------------------------------------------------------
# Scene
# ---------------------------------------------------------------------------


def _severity_counts(findings: Iterable[Any]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for finding in findings:
        sev = finding.severity.value if isinstance(finding.severity, Severity) else finding.severity
        for key in {finding.resource_id, finding.resource_arn}:
            if key:
                counts[key][str(sev)] += 1
    return counts


def _containment(
    assets: list[CloudAsset], edges: list[dict[str, Any]], by_id: dict[str, CloudAsset]
) -> dict[str, str]:
    """child asset id -> its network or subnet asset id."""
    by_name: dict[str, str] = {}
    for asset in assets:
        if asset.asset_type.value in _NETWORK_TYPES | _SUBNET_TYPES:
            for key in (asset.id, asset.arn, asset.name, asset.metadata.get("vpc_id")):
                if key:
                    by_name.setdefault(str(key), asset.id)
            subnet_key = asset.metadata.get("subnet_id")
            if subnet_key:
                by_name.setdefault(str(subnet_key), asset.id)
    parent: dict[str, str] = {}
    for edge in edges:
        if edge["type"] != "CONTAINS":
            continue
        src, dst = by_id.get(edge["source"]), by_id.get(edge["target"])
        if src and dst and src.asset_type.value in _NETWORK_TYPES | _SUBNET_TYPES:
            parent.setdefault(dst.id, src.id)
    for asset in assets:
        if asset.id in parent:
            continue
        for key in ("subnet_id", "vpc_id"):
            ref = asset.metadata.get(key)
            if ref and str(ref) in by_name and by_name[str(ref)] != asset.id:
                parent[asset.id] = by_name[str(ref)]
                break
    return parent


def _ancestors(asset_id: str, parent: dict[str, str]) -> list[str]:
    chain, seen = [], set()
    while asset_id in parent and asset_id not in seen:
        seen.add(asset_id)
        asset_id = parent[asset_id]
        chain.append(asset_id)
    return chain


def _normalise_edges(
    graph: dict[str, Any] | None, edges: list[NetworkEdge]
) -> list[dict[str, Any]]:
    """Edges as plain dicts, from the graph export when there is one."""
    out: list[dict[str, Any]] = []
    if graph and graph.get("links"):
        for link in graph["links"]:
            if "relation" in link and "type" not in link:
                continue  # finding and framework links added for the 2D map
            out.append(
                {
                    "source": str(link.get("source")),
                    "target": str(link.get("target")),
                    "type": str(link.get("type") or "REFERENCES"),
                    "relationship": link.get("relationship") or None,
                    "port_range": link.get("port_range"),
                    "protocol": link.get("protocol"),
                    "description": link.get("description") or "",
                }
            )
        return out
    for edge in edges:
        out.append(
            {
                "source": edge.source_id,
                "target": edge.target_id,
                "type": edge.edge_type.value,
                "relationship": edge.relationship,
                "port_range": edge.port_range,
                "protocol": edge.protocol,
                "description": edge.description or "",
            }
        )
    return out


def _is_internet(node_id: str) -> bool:
    return node_id in ("0.0.0.0/0", "::/0", "internet", "INTERNET") or node_id.endswith("/0")


class _Router:
    """Assigns each trace a port at both ends and a lane that is its own."""

    def __init__(self) -> None:
        # (axis, lane index) -> [(fixed coordinate, lo, hi)]
        self._runs: dict[tuple[str, int], list[tuple[float, float, float]]] = defaultdict(list)
        self._ports: dict[str, int] = defaultdict(int)

    def port(self, node: dict[str, Any]) -> list[float]:
        """The next free port on a node's top face, spiralling out from its centre."""
        index = self._ports[node["id"]]
        self._ports[node["id"]] += 1
        if index == 0:
            ox = oy = 0.0
        else:
            angle = index * 2.399963  # golden angle
            radius = min(PORT_STEP * math.sqrt(index), max(node["w"], node["d"]) * 0.42)
            ox, oy = radius * math.cos(angle), radius * math.sin(angle)
        return [node["x"] + ox, node["y"] + oy, node["z"] + node["h"]]

    def _clear(self, axis: str, lane: int, fixed: float, lo: float, hi: float) -> bool:
        if hi - lo < 1e-6:
            return True
        for f, a, b in self._runs[(axis, lane)]:
            if abs(f - fixed) < 1.2 and a < hi - 0.5 and lo < b - 0.5:
                return False
        return True

    def _claim(self, axis: str, lane: int, fixed: float, lo: float, hi: float) -> None:
        if hi - lo >= 1e-6:
            self._runs[(axis, lane)].append((fixed, lo, hi))

    def route(self, start: list[float], end: list[float], floor: float) -> list[list[float]]:
        """An orthogonal route from start to end whose runs are on a free lane above floor."""
        (sx, sy, _), (tx, ty, _) = start, end
        base = math.ceil(floor / LANE_STEP)
        for lane in range(base, base + 4000):
            z = lane * LANE_STEP
            # x first: a run along x at y=sy, then along y at x=tx
            if self._clear("x", lane, sy, min(sx, tx), max(sx, tx)) and self._clear(
                "y", lane, tx, min(sy, ty), max(sy, ty)
            ):
                self._claim("x", lane, sy, min(sx, tx), max(sx, tx))
                self._claim("y", lane, tx, min(sy, ty), max(sy, ty))
                return [start, [sx, sy, z], [tx, sy, z], [tx, ty, z], end]
            # y first: along y at x=sx, then along x at y=ty
            if self._clear("y", lane, sx, min(sy, ty), max(sy, ty)) and self._clear(
                "x", lane, ty, min(sx, tx), max(sx, tx)
            ):
                self._claim("y", lane, sx, min(sy, ty), max(sy, ty))
                self._claim("x", lane, ty, min(sx, tx), max(sx, tx))
                return [start, [sx, sy, z], [sx, ty, z], [tx, ty, z], end]
        raise RuntimeError("no free trace lane")  # pragma: no cover (4000 lanes)


def _r(value: float) -> float:
    return round(value, 2)


def build_scene(scan: ScanResult, graph: dict[str, Any] | None = None) -> dict[str, Any]:
    """The isometric scene for ``scan``: platforms, nodes, traces and bounds.

    ``graph`` is the ``to_d3_json()`` export of the scan's graph when there
    is one; its links (and its external nodes, such as ``0.0.0.0/0``) are
    used for the traces. Without it the scan's own edges are used.
    """
    assets = list(scan.assets)
    if len(assets) > MAX_SCENE_ASSETS:
        return {"too_large": True, "asset_count": len(assets), "limit": MAX_SCENE_ASSETS}

    by_id = {a.id: a for a in assets}
    alias: dict[str, str] = {}
    for asset in assets:
        alias[asset.id] = asset.id
        if asset.arn:
            alias.setdefault(asset.arn, asset.id)
    edges = _normalise_edges(graph, list(scan.edges))
    findings = _severity_counts(scan.findings)
    parent = _containment(assets, edges, by_id)

    # ── Build the container tree ──
    providers: dict[str, _Box] = {}
    regions: dict[tuple[str, str, str], _Box] = {}
    containers: dict[str, _Box] = {}
    decks: dict[str, _Box] = {}
    deck_nodes: set[str] = set()

    def provider_box(name: str) -> _Box:
        if name not in providers:
            providers[name] = _Box(f"p:{name}", "provider", name)
            decks[name] = _Box(f"d:{name}", "deck", f"{name} control plane")
        return providers[name]

    def region_box(asset: CloudAsset) -> _Box:
        prov = asset.provider.value
        key = (prov, asset.account_id or "", asset.region or "global")
        if key not in regions:
            label = " · ".join(p for p in (asset.account_id, asset.region) if p) or prov
            regions[key] = _Box(f"r:{'/'.join(key)}", "region", label)
            provider_box(prov).children.append(regions[key])
        return regions[key]

    # Networks and subnets first, so assets can land in them
    for asset in sorted(assets, key=lambda a: (a.asset_type.value not in _NETWORK_TYPES, a.name)):
        kind = (
            "network"
            if asset.asset_type.value in _NETWORK_TYPES
            else "subnet"
            if asset.asset_type.value in _SUBNET_TYPES
            else None
        )
        if not kind:
            continue
        containers[asset.id] = _Box(f"c:{asset.id}", kind, asset.name, asset=asset)
    for cid, box in containers.items():
        holder = parent.get(cid)
        if holder in containers and holder != cid:
            containers[holder].children.append(box)
        else:
            region_box(box.asset).children.append(box)  # type: ignore[arg-type]

    for asset in sorted(assets, key=lambda a: (a.asset_type.value, a.name, a.id)):
        if asset.id in containers:
            continue
        category = category_of(asset.asset_type.value)
        shape, w, d, h, plane = _SHAPES[category]
        box = _Box(f"a:{asset.id}", "asset", asset.name, asset=asset)
        box.meta.update(category=category, shape=shape, fw=w, fd=d, h=h)
        holder = next((c for c in _ancestors(asset.id, parent) if c in containers), None)
        global_scope = (asset.region or "global") == "global"
        if holder:
            containers[holder].children.append(box)
        elif plane == "deck" or global_scope:
            provider_box(asset.provider.value)
            decks[asset.provider.value].children.append(box)
            deck_nodes.add(asset.id)
        else:
            region_box(asset).children.append(box)

    # External graph nodes (the internet, accounts outside the estate)
    external_ids: list[str] = []
    for edge in edges:
        for end in (edge["source"], edge["target"]):
            if end not in alias and end not in external_ids:
                external_ids.append(end)

    # ── Size and place ──
    cursor_x = 0.0
    provider_order = sorted(providers, key=lambda p: {"AWS": 0, "AZURE": 1, "GCP": 2}.get(p, 3))
    deck_gap = 22.0
    for name in provider_order:
        base = providers[name]
        _size(base)
        deck = decks[name]
        if deck.children:
            _size(deck)
        base.w = max(base.w, deck.w if deck.children else 0.0)
        _place(base, cursor_x, 0.0)
        if deck.children:
            _place(deck, cursor_x, -(deck.d + deck_gap))
        cursor_x += base.w + GAP * 5

    platforms: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    node_by_id: dict[str, dict[str, Any]] = {}

    def emit(box: _Box, z: float, provider: str, depth: int, parent_key: str | None) -> None:
        heights = {"provider": BASE_H, "region": REGION_H, "network": NETWORK_H, "deck": DECK_H}
        height = heights.get(box.kind, SUBNET_H)
        platforms.append(
            {
                "id": box.key,
                "kind": box.kind,
                "label": box.label,
                "provider": provider,
                "asset_id": box.asset.id if box.asset else None,
                "parent": parent_key,
                "x": _r(box.x),
                "y": _r(box.y),
                "w": _r(box.w),
                "d": _r(box.d),
                "z": _r(z),
                "h": height,
                "level": depth,
            }
        )
        top = z + height
        for child in box.children:
            if child.kind == "asset":
                emit_asset(child, top, provider, box.key)
            else:
                emit(child, top, provider, depth + 1, box.key)

    def emit_asset(box: _Box, z: float, provider: str, parent_key: str) -> None:
        asset = box.asset
        assert asset is not None
        sev = findings.get(asset.id) or findings.get(asset.arn or "") or {}
        worst = next((s for s in _SEVERITY_ORDER if sev.get(s)), None)
        node = {
            "id": asset.id,
            "name": asset.name,
            "type": asset.asset_type.value,
            "category": box.meta["category"],
            "shape": box.meta["shape"],
            "provider": provider,
            "region": asset.region,
            "account": asset.account_id or "",
            "arn": asset.arn or "",
            "exposed": bool(asset.is_internet_exposed),
            "x": _r(box.x + CELL / 2),
            "y": _r(box.y + CELL / 2),
            "z": _r(z),
            "w": box.meta["fw"],
            "d": box.meta["fd"],
            "h": box.meta["h"],
            "findings": {k: v for k, v in sev.items() if v},
            "worst": worst,
            "parent": parent_key,
        }
        nodes.append(node)
        node_by_id[asset.id] = node

    for name in provider_order:
        emit(providers[name], 0.0, name, 0, None)
        if decks[name].children:
            emit(decks[name], 0.0, name, 1, None)

    ground_top = max((n["z"] + n["h"] for n in nodes if n["id"] not in deck_nodes), default=BASE_H)
    scene_max_y = max((p["y"] + p["d"] for p in platforms), default=0.0)
    scene_max_x = max((p["x"] + p["w"] for p in platforms), default=0.0)

    # The internet mast stands in front of the bench; other externals beside it
    externals: list[dict[str, Any]] = []
    ext_x = scene_max_x * 0.5
    ext_y = scene_max_y + 46.0
    others = 0
    for ext in external_ids:
        if _is_internet(ext):
            node = {"id": ext, "x": _r(ext_x), "y": _r(ext_y), "z": 0.0, "w": 14, "d": 14, "h": 34}
            kind = "internet"
        else:
            node = {
                "id": ext,
                "x": _r(ext_x + 40 + others * 22),
                "y": _r(ext_y),
                "z": 0.0,
                "w": 9,
                "d": 9,
                "h": 8,
            }
            others += 1
            kind = "external"
        node.update(name=ext, kind=kind)
        externals.append(node)
        node_by_id[ext] = node

    # Ground lanes run under the deck; deck lanes run above it
    router = _Router()
    pending: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any], bool]] = []
    seen_pairs: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edge in edges:
        if edge["type"] == "CONTAINS":
            continue  # shown by where things stand
        src = node_by_id.get(alias.get(edge["source"], edge["source"]))
        dst = node_by_id.get(alias.get(edge["target"], edge["target"]))
        if not src or not dst or src is dst:
            continue
        rel = edge["relationship"] or ""
        key = (src["id"], dst["id"], edge["type"], rel)
        if key in seen_pairs:
            seen_pairs[key]["count"] += 1
            continue
        uses_deck = src["id"] in deck_nodes or dst["id"] in deck_nodes
        record = {"edge": edge, "count": 1}
        seen_pairs[key] = record
        pending.append((src, dst, record, uses_deck))

    # Route ground-only traces first; the deck then floats above the tallest lane
    traces: list[dict[str, Any]] = []
    ground_ceiling = ground_top

    def emit_trace(src: dict[str, Any], dst: dict[str, Any], record: dict[str, Any], floor: float):
        edge = record["edge"]
        family = edge_family(edge["type"], edge["relationship"])
        start, end = router.port(src), router.port(dst)
        points = router.route(start, end, floor + _FAMILY_LIFT[family])
        traces.append(
            {
                "id": f"t{len(traces)}",
                "source": src["id"],
                "target": dst["id"],
                "type": edge["type"],
                "relationship": edge["relationship"],
                "family": family,
                "label": edge["relationship"] or edge["type"],
                "ports": edge["port_range"],
                "protocol": edge["protocol"],
                "description": edge["description"],
                "count": record["count"],
                "points": [[_r(v) for v in p] for p in points],
            }
        )
        return points

    for src, dst, record, uses_deck in pending:
        if uses_deck:
            continue
        floor = max(src["z"] + src["h"], dst["z"] + dst["h"]) + LANE_CLEAR
        points = emit_trace(src, dst, record, floor)
        ground_ceiling = max(ground_ceiling, max(p[2] for p in points))

    deck_z = ground_ceiling + 10.0
    for platform in platforms:
        if platform["kind"] == "deck":
            platform["z"] = _r(platform["z"] + deck_z)
    for node in nodes:
        if node["id"] in deck_nodes:
            node["z"] = _r(node["z"] + deck_z)
    deck_top = max((n["z"] + n["h"] for n in nodes if n["id"] in deck_nodes), default=deck_z)

    for src, dst, record, uses_deck in pending:
        if not uses_deck:
            continue
        floor = max(src["z"] + src["h"], dst["z"] + dst["h"], deck_top) + LANE_CLEAR
        emit_trace(src, dst, record, floor)

    xs = [p["x"] for p in platforms] + [p["x"] + p["w"] for p in platforms]
    ys = [p["y"] for p in platforms] + [p["y"] + p["d"] for p in platforms]
    xs += [e["x"] - e["w"] for e in externals] + [e["x"] + e["w"] for e in externals]
    ys += [e["y"] - e["d"] for e in externals] + [e["y"] + e["d"] for e in externals]
    top = max([deck_top] + [max(p[2] for p in t["points"]) for t in traces] + [ground_top])
    return {
        "version": 1,
        "units": "world",
        "platforms": platforms,
        "decks": [
            {"provider": p["provider"], "id": p["id"], "z": p["z"]}
            for p in platforms
            if p["kind"] == "deck"
        ],
        "nodes": nodes,
        "externals": externals,
        "traces": traces,
        "bounds": {
            "x": [_r(min(xs, default=0)), _r(max(xs, default=0))],
            "y": [_r(min(ys, default=0)), _r(max(ys, default=0))],
            "z": [0.0, _r(top)],
        },
        "families": sorted({t["family"] for t in traces}),
    }
