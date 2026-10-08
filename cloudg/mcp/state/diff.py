"""Comparing two datasets (drift / change review)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cloudg.mcp.state.dataset import Dataset
from cloudg.schema.models import CloudAsset


def _asset_fingerprint(a: CloudAsset) -> dict[str, Any]:
    return {
        "name": a.name,
        "type": a.asset_type.value,
        "region": a.region,
        "account_id": a.account_id,
        "tags": a.tags,
        "internet_exposed": a.is_internet_exposed,
        "metadata_hash": hashlib.sha256(
            json.dumps(a.metadata, sort_keys=True, default=str).encode()
        ).hexdigest()[:16],
    }


def _asset_map(ds: Dataset) -> dict[str, CloudAsset]:
    return {(a.arn or a.id): a for a in ds.assets}


def _brief(a: CloudAsset) -> dict[str, Any]:
    return {
        "id": a.id,
        "key": a.arn or a.id,
        "name": a.name,
        "type": a.asset_type.value,
        "account_id": a.account_id,
        "region": a.region,
    }


def _changed_assets(ba: dict[str, CloudAsset], ta: dict[str, CloudAsset]) -> list[dict[str, Any]]:
    changed = []
    for k in sorted(ba.keys() & ta.keys()):
        fb, ft = _asset_fingerprint(ba[k]), _asset_fingerprint(ta[k])
        if fb == ft:
            continue
        fields = sorted(f for f in fb if fb[f] != ft[f])
        entry = {**_brief(ta[k]), "changed_fields": fields}
        if "internet_exposed" in fields:
            entry["internet_exposed"] = {
                "before": fb["internet_exposed"],
                "after": ft["internet_exposed"],
            }
        changed.append(entry)
    return changed


def _edge_keys(ds: Dataset) -> dict[tuple, dict[str, Any]]:
    out = {}
    for e in ds.edges:
        key = (
            ds.asset_key(e.source_id),
            ds.asset_key(e.target_id),
            e.edge_type.value,
            e.relationship or "",
        )
        out[key] = {
            "source": key[0],
            "target": key[1],
            "edge_type": key[2],
            "relationship": e.relationship,
        }
    return out


def _finding_keys(ds: Dataset) -> dict[tuple, dict[str, Any]]:
    out = {}
    for f in ds.findings:
        aid = ds.finding_asset_id(f)
        res = ds.asset_key(aid) if aid else (f.resource_arn or f.resource_id)
        key = (f.source_tool, f.source_finding_id or f.title, res)
        out[key] = {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "resource": res,
            "source_tool": f.source_tool,
        }
    return out


def _findings_section(base: Dataset, target: Dataset) -> dict[str, list[dict[str, Any]]]:
    bf, tf = _finding_keys(base), _finding_keys(target)
    return {
        "new": [tf[k] for k in sorted(tf.keys() - bf.keys(), key=str)],
        "resolved": [bf[k] for k in sorted(bf.keys() - tf.keys(), key=str)],
        "severity_changed": [
            {**tf[k], "severity_before": bf[k]["severity"]}
            for k in sorted(bf.keys() & tf.keys(), key=str)
            if bf[k]["severity"] != tf[k]["severity"]
        ],
    }


def diff_datasets(base: Dataset, target: Dataset, limit: int = 50) -> dict[str, Any]:
    """What changed from ``base`` to ``target``. Assets are matched on ARN
    (else id), edges on (source, target, type, relationship) over those
    keys, findings on (source tool, check / title, resource)."""

    def section(items: list[Any]) -> dict[str, Any]:
        return {"count": len(items), "items": items[:limit], "truncated": len(items) > limit}

    ba, ta = _asset_map(base), _asset_map(target)
    added = [_brief(ta[k]) for k in sorted(ta.keys() - ba.keys())]
    removed = [_brief(ba[k]) for k in sorted(ba.keys() - ta.keys())]
    changed = _changed_assets(ba, ta)
    be, te = _edge_keys(base), _edge_keys(target)
    findings = _findings_section(base, target)
    newly_exposed = [
        c
        for c in changed
        if isinstance(c.get("internet_exposed"), dict) and c["internet_exposed"]["after"]
    ] + [a for a in added if ta[a["key"]].is_internet_exposed]
    return {
        "base": base.name,
        "target": target.name,
        "assets": {
            "added": section(added),
            "removed": section(removed),
            "changed": section(changed),
            "unchanged": len(ba.keys() & ta.keys()) - len(changed),
        },
        "edges": {
            "added": section([te[k] for k in sorted(te.keys() - be.keys())]),
            "removed": section([be[k] for k in sorted(be.keys() - te.keys())]),
        },
        "findings": {k: section(v) for k, v in findings.items()},
        "newly_internet_exposed": section(newly_exposed),
    }
