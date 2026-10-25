"""Backup and platform sources: Backup and DR Service, Firestore backups and
schedules, Apigee target servers and deployments, Infrastructure Manager
managed resources and Deployment Manager deployments."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.gcp_relations.names import full_name
from cloudg.inventory.gcp_sources.base import SourceContext, SourceRun, source
from cloudg.schema.models import CloudAsset, EdgeType

_BDR = "https://backupdr.googleapis.com/v1"
_FS = "https://firestore.googleapis.com/v1"
_APIGEE = "https://apigee.googleapis.com/v1"
_IM = "https://config.googleapis.com/v1"
_DM = "https://deploymentmanager.googleapis.com/deploymentmanager/v2"


def _append(asset: CloudAsset, relation: dict[str, Any] | None) -> None:
    if relation:
        rels = asset.metadata.setdefault("relations", [])
        if relation not in rels:
            rels.append(relation)


def _location(name: str) -> str | None:
    parts = name.split("/")
    return parts[parts.index("locations") + 1] if "locations" in parts[:-1] else None


# ---------------------------------------------------------------------------
# Backup and DR Service
# ---------------------------------------------------------------------------


@source("backup_dr", "backup")
def backup_dr(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Backup and DR vaults, plans, plan associations and management servers (BACKUP_TO)."""
    kinds = (
        ("backupVaults", "backupdr.googleapis.com/BackupVault"),
        ("backupPlans", "backupdr.googleapis.com/BackupPlan"),
        ("backupPlanAssociations", "backupdr.googleapis.com/BackupPlanAssociation"),
        ("managementServers", "backupdr.googleapis.com/ManagementServer"),
    )
    out: list[CloudAsset] = []
    for project, _number in ctx.projects():
        for key, kind in kinds:
            url = f"{_BDR}/projects/{project}/locations/-/{key}"
            for item in ctx.items(run, url, key):
                name = item.get("name")
                if isinstance(name, str):
                    out.append(
                        ctx.build(
                            f"//backupdr.googleapis.com/{name}",
                            kind,
                            item,
                            project=project,
                            location=_location(name),
                            source_name="backup_dr",
                        )
                    )
    return [a for a in out if a is not None]


@source("firestore_backups", "backup")
def firestore_backups(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Firestore backup schedules (per database) and backups (per project)."""
    out: list[CloudAsset] = []
    databases = ctx.by_type("firestore.googleapis.com/Database")
    projects = sorted({db.account_id for db in databases if db.account_id})
    for db in databases:
        rel_name = db.arn.split("firestore.googleapis.com/", 1)[-1]
        for sched in ctx.items(run, f"{_FS}/{rel_name}/backupSchedules", "backupSchedules"):
            if isinstance(sched.get("name"), str):
                out.append(
                    ctx.build(
                        f"//firestore.googleapis.com/{sched['name']}",
                        "firestore.googleapis.com/BackupSchedule",
                        sched,
                        project=db.account_id,
                        source_name="firestore_backups",
                    )
                )
    for project in projects:
        for backup in ctx.items(run, f"{_FS}/projects/{project}/locations/-/backups", "backups"):
            if isinstance(backup.get("name"), str):
                out.append(
                    ctx.build(
                        f"//firestore.googleapis.com/{backup['name']}",
                        "firestore.googleapis.com/Backup",
                        backup,
                        project=project,
                        location=_location(backup["name"]),
                        source_name="firestore_backups",
                    )
                )
    return [a for a in out if a is not None]


# ---------------------------------------------------------------------------
# Apigee
# ---------------------------------------------------------------------------


def _names(body: Any, key: str) -> list[str]:
    """Apigee lists come back as bare names or as ``{key: [{name: ...}]}``."""
    if isinstance(body, list):
        return [str(n) for n in body]
    if isinstance(body, dict):
        items = body.get(key) or body.get("items") or []
        if isinstance(items, str):
            items = [items]
        return [str(i.get("name") if isinstance(i, dict) else i) for i in items]
    return []


@source("apigee", "serverless")
def apigee(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Apigee environments' target servers and proxy deployments."""
    out: list[CloudAsset] = []
    for org_asset in ctx.by_type("apigee.googleapis.com/Organization"):
        org = org_asset.arn.rsplit("/", 1)[-1]
        project = org_asset.account_id
        envs = _names(ctx.get(run, f"{_APIGEE}/organizations/{org}/environments"), "environments")
        for env in envs:
            ts_body = ctx.get(
                run, f"{_APIGEE}/organizations/{org}/environments/{env}/targetservers"
            )
            for ts in _names(ts_body, "targetServers"):
                detail = ctx.get(
                    run, f"{_APIGEE}/organizations/{org}/environments/{env}/targetservers/{ts}"
                )
                if detail:
                    out.append(
                        ctx.build(
                            f"//apigee.googleapis.com/organizations/{org}/environments/{env}/targetservers/{ts}",
                            "apigee.googleapis.com/TargetServer",
                            detail,
                            project=project,
                            source_name="apigee",
                        )
                    )
        body = ctx.get(run, f"{_APIGEE}/organizations/{org}/deployments") or {}
        for dep in body.get("deployments") or []:
            proxy = ctx.lookup(
                f"//apigee.googleapis.com/organizations/{org}/apis/{dep.get('apiProxy')}"
            )
            env = dep.get("environment")
            if proxy is not None and env:
                _append(
                    proxy,
                    rel(
                        f"//apigee.googleapis.com/organizations/{org}/environments/{env}",
                        EdgeType.ATTACHED_TO,
                        description=f"revision {dep.get('revision')} deployed",
                        revision=dep.get("revision"),
                    ),
                )
    return [a for a in out if a is not None]


# ---------------------------------------------------------------------------
# Infrastructure Manager and Deployment Manager
# ---------------------------------------------------------------------------


@source("infra_manager", "iac")
def infra_manager(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Resources each Infrastructure Manager deployment's latest revision manages (MANAGES)."""
    for dep in ctx.by_type("config.googleapis.com/Deployment"):
        revision = ((dep.raw_data or {}).get("data") or {}).get("latestRevision")
        if not isinstance(revision, str) or not revision:
            continue
        managed = []
        for res in ctx.items(run, f"{_IM}/{revision}/resources", "resources"):
            for cai in (res.get("caiAssets") or {}).values():
                ref = full_name(cai.get("fullResourceName")) if isinstance(cai, dict) else None
                if ref:
                    managed.append(ref)
                    _append(
                        dep,
                        rel(
                            ref,
                            EdgeType.MANAGES,
                            "OWNED_BY",
                            description="Terraform-managed resource",
                        ),
                    )
        dep.metadata["managed_resource_count"] = len(managed)
    return []


@source("deployment_manager", "iac")
def deployment_manager(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Deployment Manager deployments and the resources they created (MANAGES)."""
    out: list[CloudAsset] = []
    for project, _number in ctx.projects():
        base = f"{_DM}/projects/{project}/global/deployments"
        for dep in ctx.items(run, base, "deployments", page_size=500, page_size_param="maxResults"):
            name = dep.get("name")
            if not isinstance(name, str):
                continue
            resources = ctx.items(
                run,
                f"{base}/{name}/resources",
                "resources",
                page_size=500,
                page_size_param="maxResults",
            )
            data = {
                **dep,
                "resources": [{k: r.get(k) for k in ("name", "type", "url")} for r in resources],
            }
            out.append(
                ctx.build(
                    f"//deploymentmanager.googleapis.com/projects/{project}/global/deployments/{name}",
                    "deploymentmanager.googleapis.com/Deployment",
                    data,
                    project=project,
                    source_name="deployment_manager",
                )
            )
    return [a for a in out if a is not None]
