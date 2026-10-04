"""Cloud Asset Inventory record -> :class:`CloudAsset` mapping for the GCP collector.

Pure helpers used by :class:`~cloudg.collectors.gcp.GCPCollector`: converting
API results to plain records, building assets from a record plus what the
:mod:`cloudg.inventory.gcp_relations` extractors found, evaluating VPC
firewall rules against instances, and turning exposure entries into
internet ingress edges.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType, NetworkEdge

_PROJECT_SEG_RE = re.compile(r"/projects/([^/]+)/")
_INTERNET = "0.0.0.0/0"
_FIREWALL = "compute.googleapis.com/Firewall"
_INSTANCE = "compute.googleapis.com/Instance"
# Hierarchy nodes are not owned by a project
_NO_ACCOUNT_TYPES = (
    "cloudresourcemanager.googleapis.com/Organization",
    "cloudresourcemanager.googleapis.com/Folder",
)


def _project_segment(name: str) -> str | None:
    m = _PROJECT_SEG_RE.search(name + "/")
    seg = m.group(1) if m else None
    return seg if seg not in (None, "_", "-") else None


def to_plain(obj: Any) -> Any:
    """Convert proto-plus / raw protobuf / plain objects into dicts."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, (list, tuple)):
        return [to_plain(i) for i in obj]
    cls = type(obj)
    if hasattr(cls, "to_dict") and hasattr(cls, "meta"):
        return cls.to_dict(obj)
    if hasattr(obj, "DESCRIPTOR"):
        from google.protobuf.json_format import MessageToDict

        return MessageToDict(obj, preserving_proto_field_name=True)
    if hasattr(obj, "__dict__"):
        return {k: to_plain(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return obj


def state_str(value: Any) -> str | None:
    """Resource state as a string; the CAI API returns plain strings, older
    clients and tests may hand back enum-like objects."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return value
    name = getattr(value, "name", None)
    return name if isinstance(name, str) else str(value)


def _num(value: Any) -> str | None:
    """Struct numbers arrive as floats; render integers without '.0'."""
    if value in (None, ""):
        return None
    return str(int(value)) if isinstance(value, float) and value.is_integer() else str(value)


def extract_location(name: str) -> str:
    """Extract region/zone from resource name."""
    parts = name.split("/")
    for i, part in enumerate(parts):
        if part in ("zones", "regions", "locations") and i + 1 < len(parts):
            return parts[i + 1]
    return "global"


# ---------------------------------------------------------------------------
# API results -> records
# ---------------------------------------------------------------------------


def record_from_asset(d: dict[str, Any]) -> dict[str, Any]:
    """A ListAssets result as a record (full resource JSON)."""
    res = d.get("resource") or {}
    return {
        "name": d.get("name") or "",
        "asset_type": d.get("asset_type") or d.get("assetType") or "",
        "data": res.get("data") or {},
        "location": res.get("location") or "",
        "parent": res.get("parent") or "",
        "ancestors": list(d.get("ancestors") or []),
        "update_time": d.get("update_time") or d.get("updateTime"),
    }


def record_from_search(d: dict[str, Any]) -> dict[str, Any]:
    """A SearchAllResources result in the ListAssets record shape (summary only)."""

    def g(snake: str, camel: str) -> Any:
        return d.get(snake, d.get(camel))

    project = g("project", "project") or ""
    ancestors = [project] if project else []
    ancestors += list(g("folders", "folders") or [])
    if g("organization", "organization"):
        ancestors.append(g("organization", "organization"))
    return {
        "name": d.get("name") or "",
        "asset_type": g("asset_type", "assetType") or "",
        "data": {},
        "location": d.get("location") or "",
        "parent": g("parent_full_resource_name", "parentFullResourceName") or "",
        "ancestors": ancestors,
        "summary": {
            "display_name": g("display_name", "displayName"),
            "description": d.get("description"),
            "state": state_str(d.get("state")),
            "labels": dict(d.get("labels") or {}),
            "network_tags": list(g("network_tags", "networkTags") or []),
            "kms_keys": list(g("kms_keys", "kmsKeys") or []),
            "create_time": g("create_time", "createTime"),
            "parent_asset_type": g("parent_asset_type", "parentAssetType"),
        },
    }


# ---------------------------------------------------------------------------
# Record -> CloudAsset
# ---------------------------------------------------------------------------


def display_name(rec: dict[str, Any], data: dict[str, Any]) -> str:
    """Human-readable name of a record (email, project ID, display name, ...)."""
    atype = rec["asset_type"]
    if atype == "iam.googleapis.com/ServiceAccount" and data.get("email"):
        return str(data["email"])
    if atype == "cloudresourcemanager.googleapis.com/Project" and data.get("projectId"):
        return str(data["projectId"])
    if atype == "compute.googleapis.com/Project":
        return f"compute settings ({data.get('name') or rec['name'].rsplit('/', 1)[-1]})"
    for key in ("displayName", "display_name"):
        if isinstance(data.get(key), str) and data[key]:
            return data[key]
    meta_name = (
        (data.get("metadata") or {}).get("name") if isinstance(data.get("metadata"), dict) else None
    )
    if isinstance(meta_name, str) and meta_name:
        return meta_name
    name = data.get("name")
    if isinstance(name, str) and name:
        return name.rsplit("/", 1)[-1]
    summary = rec.get("summary") or {}
    if summary.get("display_name"):
        return str(summary["display_name"])
    return rec["name"].rstrip("/").rsplit("/", 1)[-1] or rec["name"]


def asset_location(rec: dict[str, Any], data: dict[str, Any]) -> Any:
    """Short region / zone of a record (``global`` when none applies)."""
    location = (
        rec.get("location")
        or data.get("region")
        or data.get("zone")
        or extract_location(rec["name"])
    )
    if isinstance(location, str) and "/" in location:
        location = location.rsplit("/", 1)[-1]
    return location


@dataclass
class MappedRecord:
    """A record being turned into an asset: scrubbed data and resolved project."""

    rec: dict[str, Any]
    data: dict[str, Any]
    project_id: str | None
    project_number: str | None
    location: Any

    @property
    def name(self) -> str:
        return self.rec["name"]

    @property
    def asset_type(self) -> str:
        return self.rec["asset_type"]

    @property
    def summary(self) -> dict[str, Any]:
        return self.rec.get("summary") or {}

    @property
    def ancestors(self) -> list[Any]:
        return self.rec.get("ancestors") or []


def _labels(data: dict[str, Any], summary: dict[str, Any]) -> Any:
    labels = data.get("labels")
    if not isinstance(labels, dict) and isinstance(data.get("metadata"), dict):
        labels = data["metadata"].get("labels")
    if not isinstance(labels, dict):
        labels = summary.get("labels") or {}
    return labels


def _state(data: dict[str, Any], summary: dict[str, Any]) -> Any:
    for key in ("status", "state", "lifecycleState"):
        if isinstance(data.get(key), str):
            return data[key] or summary.get("state")
    return summary.get("state")


def _description(data: dict[str, Any], summary: dict[str, Any]) -> Any:
    description = data.get("description") or summary.get("description")
    if isinstance(description, str) and len(description) > 500:
        description = description[:500]
    return description


def _base_metadata(m: MappedRecord) -> dict[str, Any]:
    from cloudg.inventory.gcp_relations import full_name

    data, summary, ancestors = m.data, m.summary, m.ancestors
    metadata: dict[str, Any] = {
        "gcp_asset_type": m.asset_type,
        "project": m.project_id,
        "project_id": m.project_id,
        "project_number": m.project_number,
        "folders": [a for a in ancestors if isinstance(a, str) and a.startswith("folders/")],
        "organization": next(
            (a for a in ancestors if isinstance(a, str) and a.startswith("organizations/")),
            None,
        ),
        "location": m.location,
        "state": _state(data, summary),
        "create_time": data.get("creationTimestamp")
        or data.get("createTime")
        or data.get("timeCreated")
        or summary.get("create_time"),
        "description": _description(data, summary),
        "parent_full_resource_name": m.rec.get("parent") or None,
        "parent_asset_type": summary.get("parent_asset_type"),
        "network_tags": summary.get("network_tags") or [],
    }
    if summary.get("kms_keys"):
        metadata["kms_keys"] = [full_name(k, "cloudkms") or k for k in summary["kms_keys"]]
    return metadata


def _merge_extracted(
    metadata: dict[str, Any], m: MappedRecord, ex: Any, extra_aliases: list[str]
) -> None:
    """Fold extractor metadata, relations and aliases (plus selfLink) into ``metadata``."""
    from cloudg.inventory.gcp_relations import full_name

    metadata.update({k: v for k, v in ex.metadata.items() if v is not None})
    if ex.relations:
        metadata["relations"] = ex.relations
    aliases = list(ex.aliases)
    self_link = full_name(m.data.get("selfLink"))
    for alias in [self_link, *extra_aliases]:
        if alias and alias != m.name and alias not in aliases:
            aliases.append(alias)
    if aliases:
        metadata["aliases"] = aliases
    if m.summary:
        metadata["summary_only"] = True


def build_cloud_asset(
    m: MappedRecord, ex: Any, *, name: str, asset_type: AssetType, extra_aliases: list[str]
) -> CloudAsset:
    """The CloudAsset for a mapped record and its extractor output."""
    from cloudg.inventory.gcp_relations import mark_exposed

    metadata = _base_metadata(m)
    _merge_extracted(metadata, m, ex, extra_aliases)
    labels = _labels(m.data, m.summary)
    asset = CloudAsset(
        arn=m.name,
        name=name,
        asset_type=asset_type,
        provider=CloudProvider.GCP,
        region=m.location or "global",
        account_id=None if m.asset_type in _NO_ACCOUNT_TYPES else m.project_id,
        tags={str(k): str(v) for k, v in (labels or {}).items()},
        metadata=metadata,
        raw_data={
            "name": m.name,
            "asset_type": m.asset_type,
            "ancestors": list(m.ancestors),
            "data": m.data,
        },
    )
    for entry in ex.exposure:
        mark_exposed(
            asset,
            entry["via"],
            kind=entry.get("kind"),
            protocol=entry.get("protocol"),
            ports=entry.get("ports"),
        )
    return asset


# ---------------------------------------------------------------------------
# Firewall evaluation
# ---------------------------------------------------------------------------


def _firewalls_by_network(assets: list[CloudAsset]) -> dict[str, list[CloudAsset]]:
    by_network: dict[str, list[CloudAsset]] = defaultdict(list)
    for a in assets:
        if a.metadata.get("gcp_asset_type") == _FIREWALL and a.metadata.get("network"):
            by_network[a.metadata["network"]].append(a)
    return by_network


def _targets_instance(md: dict[str, Any], sas: set[str], tags: set[str]) -> bool:
    """Target service accounts win over target tags; neither means every instance."""
    if md.get("target_service_accounts"):
        return bool(sas & set(md["target_service_accounts"]))
    if md.get("target_tags"):
        return bool(tags & set(md["target_tags"]))
    return True


def _attach_firewalls(
    inst: CloudAsset, nets: list[str], by_network: dict[str, list[CloudAsset]]
) -> list[CloudAsset]:
    """Relate the enabled rules that target ``inst``; returns them."""
    from cloudg.inventory.aws_services._base import rel

    tags = set(inst.metadata.get("network_tags") or [])
    sas = set(inst.metadata.get("service_account_emails") or [])
    matched: list[CloudAsset] = []
    for net in nets:
        for fw in by_network.get(net, []):
            md = fw.metadata
            if md.get("disabled") or not _targets_instance(md, sas, tags):
                continue
            matched.append(fw)
            r = rel(
                fw.arn,
                EdgeType.ATTACHED_TO,
                "PROTECTED_BY_SG",
                description=f"firewall rule {fw.name} applies to {inst.name}",
                direction=md.get("direction"),
                action=md.get("action"),
                priority=md.get("priority"),
            )
            rels = inst.metadata.setdefault("relations", [])
            if r and r not in rels:
                rels.append(r)
    return matched


def _fw_protocols(fw: CloudAsset) -> list[dict[str, Any]]:
    return (fw.metadata.get("ingress_rules") or [{}])[0].get("protocols", [])


def _open_rules(matched: list[CloudAsset]) -> list[CloudAsset]:
    """Internet allow rules not shadowed by a higher-priority deny-all from 0.0.0.0/0."""
    denies = [
        f
        for f in matched
        if f.metadata.get("action") == "deny"
        and f.metadata.get("internet_source")
        and any(p.get("protocol") == "all" for p in _fw_protocols(f))
    ]
    best_deny = min((f.metadata.get("priority", 1000) for f in denies), default=None)
    return [
        f
        for f in matched
        if f.metadata.get("allows_internet_ingress")
        and (best_deny is None or f.metadata.get("priority", 1000) < best_deny)
    ]


def _mark_instance_exposure(
    inst: CloudAsset,
    matched: list[CloudAsset],
    nets: list[str],
    by_network: dict[str, list[CloudAsset]],
) -> None:
    from cloudg.inventory.gcp_relations import mark_exposed

    open_rules = _open_rules(matched)
    for fw in open_rules:
        for proto in _fw_protocols(fw):
            mark_exposed(
                inst,
                f"external IP and firewall {fw.name} allows {_INTERNET}",
                kind="SECURITY_GROUP_RULE",
                protocol=proto.get("protocol"),
                ports=proto.get("ports") or None,
                firewall=fw.arn,
            )
    if not open_rules and not any(by_network.get(n) for n in nets) and nets:
        mark_exposed(inst, "external IP; no firewall rules were collected for its network")


def apply_firewalls(assets: list[CloudAsset]) -> None:
    """Attach VPC firewall rules to the instances they target and derive
    instance exposure (external IP + enabled 0.0.0.0/0 ingress allow)."""
    by_network = _firewalls_by_network(assets)
    for inst in assets:
        if inst.metadata.get("gcp_asset_type") != _INSTANCE:
            continue
        nets = inst.metadata.get("networks") or []
        matched = _attach_firewalls(inst, nets, by_network)
        if inst.metadata.get("public_ips"):
            _mark_instance_exposure(inst, matched, nets, by_network)


# ---------------------------------------------------------------------------
# Internet ingress edges
# ---------------------------------------------------------------------------


def _expand_ports(ports_raw: list[str]) -> list[int]:
    """``"80"`` / ``"8000-8080"`` strings as ports (at most 100 per range)."""
    ports: list[int] = []
    for p in ports_raw:
        lo, _, hi = p.partition("-")
        if lo.isdigit():
            end = int(hi) if hi.isdigit() else int(lo)
            ports.extend(range(int(lo), min(end, int(lo) + 99) + 1))
    return ports


def _ingress_edge(asset: CloudAsset, entry: dict[str, Any]) -> NetworkEdge:
    kind = entry.get("kind") or "INTERNET_EXPOSED"
    edge_type = (
        EdgeType.SECURITY_GROUP_RULE if kind == "SECURITY_GROUP_RULE" else EdgeType.INTERNET_EXPOSED
    )
    ports_raw = [str(p) for p in entry.get("ports") or []]
    proto = entry.get("protocol")
    return NetworkEdge(
        source_id=_INTERNET,
        target_id=asset.id,
        edge_type=edge_type,
        ports=_expand_ports(ports_raw)[:100],
        port_range=",".join(ports_raw) or None,
        protocol=("ALL" if proto in (None, "all") else str(proto).upper()),
        cidr=_INTERNET,
        direction="ingress",
        description=entry.get("via"),
        relationship="INTERNET_REACHABLE",
    )


def internet_edges(assets: list[CloudAsset]) -> list[NetworkEdge]:
    """``0.0.0.0/0`` -> asset edges for every recorded internet ingress entry."""
    return [
        _ingress_edge(a, entry)
        for a in assets
        for entry in a.metadata.get("internet_ingress") or []
    ]
