"""Operations sources: Cloud DNS record sets, Cloud Monitoring (alert
policies, notification channels, uptime checks, metrics scopes), OS Config
and Cloud Scheduler jobs."""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.gcp_sources.base import SourceContext, SourceRun, source
from cloudg.schema.models import CloudAsset, EdgeType

_DNS = "https://dns.googleapis.com/dns/v1"
_MON3 = "https://monitoring.googleapis.com/v3"
_MON1 = "https://monitoring.googleapis.com/v1"
_OSC = "https://osconfig.googleapis.com/v1"
_SCHED = "https://cloudscheduler.googleapis.com/v1"
_CRM = "//cloudresourcemanager.googleapis.com/"
_REGION_RE = re.compile(r"^[a-z]+-[a-z]+\d+$")
_APPENGINE_REGIONS = {"us-central": "us-central1", "europe-west": "europe-west1"}


def _append(asset: CloudAsset, relation: dict[str, Any] | None) -> None:
    if relation:
        rels = asset.metadata.setdefault("relations", [])
        if relation not in rels:
            rels.append(relation)


# ---------------------------------------------------------------------------
# Cloud DNS record sets
# ---------------------------------------------------------------------------


@source("dns_records", "dns")
def dns_records(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Record sets of every collected Cloud DNS managed zone (DNS_RESOLVED)."""
    out: list[CloudAsset] = []
    for zone in ctx.by_type("dns.googleapis.com/ManagedZone"):
        data = (zone.raw_data or {}).get("data") or {}
        project = zone.account_id
        zone_name = data.get("name") or zone.arn.rsplit("/", 1)[-1]
        if not project or not zone_name:
            continue
        records = ctx.items(
            run,
            f"{_DNS}/projects/{project}/managedZones/{zone_name}/rrsets",
            "rrsets",
            page_size=1000,
            page_size_param="maxResults",
            max_items=ctx.options.max_dns_records_per_zone,
        )
        for rr in records:
            name, rtype = rr.get("name"), rr.get("type")
            if not name or not rtype:
                continue
            asset = ctx.build(
                f"//dns.googleapis.com/projects/{project}/managedZones/{zone_name}/rrsets/{name}/{rtype}",
                "dns.googleapis.com/ResourceRecordSet",
                {**rr, "managedZone": zone.arn, "displayName": f"{name} {rtype}"},
                project=project,
                source_name="dns_records",
            )
            if asset is not None:
                out.append(asset)
    return out


# ---------------------------------------------------------------------------
# Cloud Monitoring
# ---------------------------------------------------------------------------


def _scoping_project_asset(ctx: SourceContext, project: str) -> CloudAsset | None:
    return ctx.lookup(f"{_CRM}projects/{project}")


@source("monitoring", "logging")
def monitoring(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Alert policies, notification channels and uptime checks (MONITORED_BY / INVOKES),
    and the projects each metrics scope monitors."""
    out: list[CloudAsset] = []
    kinds = (
        ("alertPolicies", "monitoring.googleapis.com/AlertPolicy"),
        ("notificationChannels", "monitoring.googleapis.com/NotificationChannel"),
        ("uptimeCheckConfigs", "monitoring.googleapis.com/UptimeCheckConfig"),
    )
    for project, number in ctx.projects():
        for key, kind in kinds:
            for item in ctx.items(run, f"{_MON3}/projects/{project}/{key}", key, page_size=500):
                name = item.get("name")
                if isinstance(name, str):
                    asset = ctx.build(
                        f"//monitoring.googleapis.com/{name}",
                        kind,
                        item,
                        project=project,
                        source_name="monitoring",
                    )
                    if asset is not None:
                        out.append(asset)
        scope = ctx.get(run, f"{_MON1}/locations/global/metricsScopes/{project}", tolerate=True)
        holder = _scoping_project_asset(ctx, project)
        for mp in (scope or {}).get("monitoredProjects") or []:
            other = str(mp.get("name") or "").rsplit("/projects/", 1)[-1]
            if holder is not None and other and other not in (project, number):
                _append(
                    holder,
                    rel(
                        f"{_CRM}projects/{other}",
                        EdgeType.MONITORS,
                        "MONITORED_BY",
                        description="project in this metrics scope",
                    ),
                )
    return out


# ---------------------------------------------------------------------------
# OS Config / VM Manager
# ---------------------------------------------------------------------------


@source("os_config", "ops")
def os_config(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Patch deployments, OS policy assignments and VM vulnerability reports."""
    zones: dict[str, set[str]] = {}
    for vm in ctx.by_type("compute.googleapis.com/Instance"):
        if vm.account_id and vm.region and vm.region != "global":
            zones.setdefault(vm.account_id, set()).add(vm.region)
    out: list[CloudAsset] = []
    for project, _number in ctx.projects():
        if project not in zones:
            continue
        for pd in ctx.items(run, f"{_OSC}/projects/{project}/patchDeployments", "patchDeployments"):
            if isinstance(pd.get("name"), str):
                out.append(
                    ctx.build(
                        f"//osconfig.googleapis.com/{pd['name']}",
                        "osconfig.googleapis.com/PatchDeployment",
                        pd,
                        project=project,
                        source_name="os_config",
                    )
                )
        for zone in sorted(zones[project]):
            base = f"{_OSC}/projects/{project}/locations/{zone}"
            for opa in ctx.items(run, f"{base}/osPolicyAssignments", "osPolicyAssignments"):
                if isinstance(opa.get("name"), str):
                    out.append(
                        ctx.build(
                            f"//osconfig.googleapis.com/{opa['name']}",
                            "osconfig.googleapis.com/OSPolicyAssignment",
                            opa,
                            project=project,
                            location=zone,
                            source_name="os_config",
                        )
                    )
            for report in ctx.items(
                run, f"{base}/instances/-/vulnerabilityReports", "vulnerabilityReports"
            ):
                if isinstance(report.get("name"), str):
                    out.append(
                        ctx.build(
                            f"//osconfig.googleapis.com/{report['name']}",
                            "osconfig.googleapis.com/VulnerabilityReport",
                            report,
                            project=project,
                            location=zone,
                            source_name="os_config",
                        )
                    )
    return [a for a in out if a is not None]


# ---------------------------------------------------------------------------
# Cloud Scheduler
# ---------------------------------------------------------------------------


def _scheduler_locations(ctx: SourceContext, project: str) -> list[str]:
    """Regions worth asking: where the project has resources, plus App Engine's."""
    regions: set[str] = set()
    for a in ctx.assets:
        if a.account_id != project or not a.region:
            continue
        region = a.region
        if re.fullmatch(r"[a-z]+-[a-z]+\d+-[a-z]", region):
            region = region.rsplit("-", 1)[0]
        if _REGION_RE.match(region):
            regions.add(region)
        if a.metadata.get("gcp_asset_type") == "appengine.googleapis.com/Application":
            loc = ((a.raw_data or {}).get("data") or {}).get("locationId")
            if isinstance(loc, str):
                regions.add(_APPENGINE_REGIONS.get(loc, loc))
    return sorted(regions)[: ctx.options.max_scheduler_locations]


@source("cloud_scheduler", "integration")
def cloud_scheduler(ctx: SourceContext, run: SourceRun) -> list[CloudAsset]:
    """Cloud Scheduler jobs (INVOKES / SCHEDULED_BY their targets)."""
    out: list[CloudAsset] = []
    for project, _number in ctx.projects():
        for loc in _scheduler_locations(ctx, project):
            for job in ctx.items(run, f"{_SCHED}/projects/{project}/locations/{loc}/jobs", "jobs"):
                if isinstance(job.get("name"), str):
                    out.append(
                        ctx.build(
                            f"//cloudscheduler.googleapis.com/{job['name']}",
                            "cloudscheduler.googleapis.com/Job",
                            job,
                            project=project,
                            location=loc,
                            source_name="cloud_scheduler",
                        )
                    )
    return [a for a in out if a is not None]
