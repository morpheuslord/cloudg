"""Serverless: Cloud Run, Cloud Functions, App Engine, Workflows, Eventarc."""

from __future__ import annotations

import json
from typing import Any

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    _list,
    dig,
    full_name,
    image_repository,
    network_ref,
    subnet_ref,
    url_alias,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Serverless
# ---------------------------------------------------------------------------


def _secret_target(ref: Any, project: str | None) -> str | None:
    if not isinstance(ref, str) or not ref:
        return None
    if "/" in ref:
        return full_name(ref.split("/versions/", 1)[0], "secretmanager")
    if project:
        return f"//secretmanager.googleapis.com/projects/{project}/secrets/{ref}"
    return None


def _cloudsql_target(conn: str) -> str | None:
    parts = conn.strip().split(":")
    if len(parts) == 3:
        return f"//cloudsql.googleapis.com/projects/{parts[0]}/instances/{parts[2]}"
    return None


def _connector_target(value: Any, project: str | None, location: str | None) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "/" in value:
        return full_name(value, "vpcaccess")
    if project and location:
        return (
            f"//vpcaccess.googleapis.com/projects/{project}/locations/{location}/connectors/{value}"
        )
    return None


def _containers(
    out: Extracted,
    containers: Any,
    env_secret: tuple[str, ...],
    project: str | None,
    secret_alias: dict[str, str] | None = None,
) -> list[str]:
    """Images of a container list (USES_IMAGE) plus the secrets their env reads.

    ``env_secret`` is the path to the secret name inside an env entry (it
    differs between the Knative v1 and the Cloud Run v2 resource shapes).
    """
    images = []
    for c in _list(containers):
        if not isinstance(c, dict):
            continue
        if c.get("image"):
            images.append(c["image"])
            out.add(image_repository(c["image"]), EdgeType.USES_IMAGE, "RUNS_ON")
        for env in _list(c.get("env")):
            ref = dig(env, *env_secret) if isinstance(env, dict) else None
            if ref and secret_alias is not None:
                ref = secret_alias.get(ref, ref)
            if ref:
                out.add(_secret_target(ref, project), EdgeType.REFERENCES, "READS_FROM")
    return images


def _run_default_sa(ctx: GCPContext) -> str | None:
    """Services fall back to the compute default identity; jobs declare none."""
    return "default" if ctx.asset_type == "run.googleapis.com/Service" else None


def _run_v1_template(ctx: GCPContext) -> tuple[dict[str, Any], dict[str, Any]]:
    """(merged service + revision annotations, revision spec) of a Knative resource."""
    d = ctx.data
    meta = d.get("metadata") or {}
    tmpl = dig(d, "spec", "template", default={}) or {}
    if ctx.asset_type == "run.googleapis.com/Job":
        tmpl = dig(tmpl, "spec", "template", default={}) or tmpl
    ann = {
        **(meta.get("annotations") or {}),
        **(dig(tmpl, "metadata", "annotations", default={}) or {}),
    }
    return ann, tmpl.get("spec") or {}


def _run_secret_aliases(ann: dict[str, Any]) -> dict[str, str]:
    """``run.googleapis.com/secrets`` annotation: alias -> secret reference."""
    secret_alias: dict[str, str] = {}
    for item in str(ann.get("run.googleapis.com/secrets", "")).split(","):
        if ":" in item:
            alias, ref = item.split(":", 1)
            secret_alias[alias.strip()] = ref.strip()
    return secret_alias


def _direct_egress(
    out: Extracted, ni: Any, where: tuple[str | None, str | None], description: str | None = None
) -> None:
    """Direct VPC egress through a network interface (subnet, else network)."""
    pid, loc = where
    out.add(
        subnet_ref(ni.get("subnetwork"), pid, loc) or network_ref(ni.get("network"), pid),
        EdgeType.ROUTE,
        "TRANSIT_ROUTED",
        description=description,
    )


def _run_v1_egress(out: Extracted, ann: dict[str, Any], pid: str | None, loc: str | None) -> None:
    """VPC connector, Cloud SQL connections and direct VPC egress from annotations."""
    connector = ann.get("run.googleapis.com/vpc-access-connector")
    out.add(
        _connector_target(connector, pid, loc),
        EdgeType.ROUTE,
        "TRANSIT_ROUTED",
        description="egress via VPC connector",
    )
    for conn in str(ann.get("run.googleapis.com/cloudsql-instances", "")).split(","):
        if conn.strip():
            out.add(
                _cloudsql_target(conn),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="Cloud SQL connection",
            )
    nis = ann.get("run.googleapis.com/network-interfaces")
    if nis:
        try:
            for ni in json.loads(nis):
                _direct_egress(out, ni, (pid, loc), "direct VPC egress")
        except (ValueError, AttributeError, TypeError):
            pass


@_extractor("run.googleapis.com/Service", "run.googleapis.com/Job")
def _cloud_run(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid = ctx.project_id
    if isinstance(d.get("template"), dict) and not isinstance(d.get("spec"), dict):
        _cloud_run_v2(ctx, out)
        return
    ann, spec = _run_v1_template(ctx)
    out.sa(
        spec.get("serviceAccountName") or _run_default_sa(ctx), ctx, "Cloud Run service identity"
    )
    secret_alias = _run_secret_aliases(ann)
    images = _containers(
        out, spec.get("containers"), ("valueFrom", "secretKeyRef", "name"), pid, secret_alias
    )
    for vol in _list(spec.get("volumes")):
        ref = dig(vol, "secret", "secretName") if isinstance(vol, dict) else None
        if ref:
            out.add(
                _secret_target(secret_alias.get(ref, ref), pid), EdgeType.REFERENCES, "READS_FROM"
            )
    _run_v1_egress(out, ann, pid, ctx.location)
    ingress = (
        ann.get("run.googleapis.com/ingress")
        or ann.get("run.googleapis.com/ingress-status")
        or "all"
    )
    url = dig(d, "status", "url") or dig(d, "status", "address", "url")
    if ctx.asset_type == "run.googleapis.com/Service" and ingress == "all":
        out.expose("Cloud Run ingress 'all'", protocol="tcp", ports=["443"])
    out.alias(url, url_alias(url))
    out.metadata.update(
        ingress=ingress,
        url=url_alias(url),
        images=images,
        vpc_egress=ann.get("run.googleapis.com/vpc-access-egress"),
    )


def _cloud_run_v2(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid, loc = ctx.project_id, ctx.location
    tmpl = d.get("template") or {}
    if ctx.asset_type == "run.googleapis.com/Job":
        tmpl = dig(tmpl, "template", default={}) or tmpl
    out.sa(tmpl.get("serviceAccount") or _run_default_sa(ctx), ctx, "Cloud Run service identity")
    images = _containers(
        out, tmpl.get("containers"), ("valueSource", "secretKeyRef", "secret"), pid
    )
    for vol in _list(tmpl.get("volumes")):
        if isinstance(vol, dict):
            out.add(
                _secret_target(dig(vol, "secret", "secret"), pid), EdgeType.REFERENCES, "READS_FROM"
            )
            for inst in _list(dig(vol, "cloudSqlInstance", "instances")):
                out.add(_cloudsql_target(inst), EdgeType.REFERENCES, "DEPENDS_ON")
    vpc = tmpl.get("vpcAccess") or {}
    out.add(_connector_target(vpc.get("connector"), pid, loc), EdgeType.ROUTE, "TRANSIT_ROUTED")
    for ni in _list(vpc.get("networkInterfaces")):
        if isinstance(ni, dict):
            _direct_egress(out, ni, (pid, loc))
    ingress = d.get("ingress") or "INGRESS_TRAFFIC_ALL"
    if ctx.asset_type == "run.googleapis.com/Service" and ingress == "INGRESS_TRAFFIC_ALL":
        out.expose("Cloud Run ingress 'all'", protocol="tcp", ports=["443"])
    for url in [d.get("uri")] + list(d.get("urls") or []):
        out.alias(url, url_alias(url))
    out.metadata.update(ingress=ingress, url=url_alias(d.get("uri")), images=images)


def _function_network(ctx: GCPContext, out: Extracted, cfg: dict[str, Any]) -> None:
    """VPC connector egress and Secret Manager references of a function (v1 or v2)."""
    pid = ctx.project_id
    out.add(
        _connector_target(cfg.get("vpcConnector"), pid, ctx.location),
        EdgeType.ROUTE,
        "TRANSIT_ROUTED",
    )
    for s in _list(cfg.get("secretEnvironmentVariables")) + _list(cfg.get("secretVolumes")):
        if isinstance(s, dict):
            out.add(
                _secret_target(s.get("secret"), s.get("projectId") or pid),
                EdgeType.REFERENCES,
                "READS_FROM",
            )


def _function_v2_trigger(out: Extracted, et: dict[str, Any]) -> None:
    """Event sources (Pub/Sub topic, Eventarc trigger, storage bucket) of a v2 function."""
    out.add(
        full_name(et.get("pubsubTopic"), "pubsub"),
        EdgeType.INVOKES,
        "INVOKES",
        reverse=True,
        event_type=et.get("eventType"),
    )
    out.add(
        full_name(et.get("trigger"), "eventarc"), EdgeType.INVOKES, "TRIGGERED_BY", reverse=True
    )
    for f in _list(et.get("eventFilters")):
        if isinstance(f, dict) and f.get("attribute") == "bucket" and f.get("value"):
            out.add(
                f"//storage.googleapis.com/{f['value']}",
                EdgeType.INVOKES,
                "INVOKES",
                reverse=True,
                event_type=et.get("eventType"),
            )


@_extractor("cloudfunctions.googleapis.com/Function")
def _function_v2(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    sc = d.get("serviceConfig") or {}
    out.sa(sc.get("serviceAccountEmail") or "default", ctx, "function runtime identity")
    out.add(
        full_name(sc.get("service"), "run"),
        EdgeType.MANAGES,
        "OWNED_BY",
        description="function runs on Cloud Run service",
    )
    _function_network(ctx, out, sc)
    et = d.get("eventTrigger") or {}
    _function_v2_trigger(out, et)
    out.add(
        full_name(dig(d, "buildConfig", "dockerRepository"), "artifactregistry"),
        EdgeType.USES_IMAGE,
        "RUNS_ON",
    )
    ingress = sc.get("ingressSettings") or "ALLOW_ALL"
    if ingress == "ALLOW_ALL" and not et:
        out.expose("Cloud Functions ingress ALLOW_ALL", protocol="tcp", ports=["443"])
    out.alias(sc.get("uri"), url_alias(sc.get("uri")), d.get("url"), url_alias(d.get("url")))
    out.metadata.update(
        ingress=ingress,
        runtime=dig(d, "buildConfig", "runtime"),
        environment=d.get("environment"),
        trigger_event_type=et.get("eventType"),
    )


@_extractor("cloudfunctions.googleapis.com/CloudFunction")
def _function_v1(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid = ctx.project_id
    out.sa(
        d.get("serviceAccountEmail") or (f"{pid}@appspot.gserviceaccount.com" if pid else None),
        ctx,
        "function runtime identity",
    )
    _function_network(ctx, out, d)
    et = d.get("eventTrigger") or {}
    resource = et.get("resource")
    if isinstance(resource, str):
        svc = "pubsub" if "/topics/" in resource else None
        out.add(
            full_name(resource, svc),
            EdgeType.INVOKES,
            "INVOKES",
            reverse=True,
            event_type=et.get("eventType"),
        )
    out.add(
        full_name(d.get("dockerRepository"), "artifactregistry"), EdgeType.USES_IMAGE, "RUNS_ON"
    )
    url = dig(d, "httpsTrigger", "url")
    ingress = d.get("ingressSettings") or "ALLOW_ALL"
    if url and ingress == "ALLOW_ALL":
        out.expose(
            "Cloud Functions HTTPS trigger, ingress ALLOW_ALL", protocol="tcp", ports=["443"]
        )
    out.alias(url, url_alias(url))
    out.metadata.update(
        ingress=ingress, runtime=d.get("runtime"), trigger_event_type=et.get("eventType")
    )


@_extractor("appengine.googleapis.com/Application")
def _app_engine(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.sa(d.get("serviceAccount"), ctx, "App Engine default identity")
    host = d.get("defaultHostname")
    if host:
        out.alias(f"https://{host.lower()}")
    out.metadata.update(default_hostname=host, serving_status=d.get("servingStatus"))


@_extractor("appengine.googleapis.com/Service")
def _app_engine_service(ctx: GCPContext, out: Extracted) -> None:
    ingress = (
        dig(ctx.data, "networkSettings", "ingressTrafficAllowed") or "INGRESS_TRAFFIC_ALLOWED_ALL"
    )
    if ingress in ("INGRESS_TRAFFIC_ALLOWED_ALL", "INGRESS_TRAFFIC_ALLOWED_UNSPECIFIED"):
        out.expose("App Engine service ingress all", protocol="tcp", ports=["443"])
    out.metadata["ingress"] = ingress


@_extractor("workflows.googleapis.com/Workflow")
def _workflow(ctx: GCPContext, out: Extracted) -> None:
    out.sa(ctx.data.get("serviceAccount"), ctx, "workflow identity")
    out.metadata["call_log_level"] = ctx.data.get("callLogLevel")


@_extractor("cloudtasks.googleapis.com/Queue")
def _tasks_queue(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.sa(
        dig(d, "httpTarget", "oidcToken", "serviceAccountEmail")
        or dig(d, "httpTarget", "oauthToken", "serviceAccountEmail"),
        ctx,
        "task identity",
    )
    out.metadata.update(
        state=d.get("state"), target_host=url_alias(dig(d, "httpTarget", "uriOverride", "host"))
    )


@_extractor("apigateway.googleapis.com/Gateway")
def _api_gateway(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("apiConfig"), "apigateway"), EdgeType.REFERENCES, "DEPENDS_ON")
    host = d.get("defaultHostname")
    if host:
        out.alias(f"https://{host.lower()}", host)
        out.expose("API Gateway public hostname", protocol="tcp", ports=["443"])
    out.metadata["default_hostname"] = host


@_extractor("apigateway.googleapis.com/ApiConfig")
def _api_config(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(ctx.name.split("/configs/", 1)[0], EdgeType.CONTAINS, reverse=True)
    out.sa(d.get("gatewayServiceAccount"), ctx, "gateway backend identity")


@_extractor("apigateway.googleapis.com/Api")
def _api(ctx: GCPContext, out: Extracted) -> None:
    out.metadata["managed_service"] = ctx.data.get("managedService")


@_extractor("eventarc.googleapis.com/Trigger")
def _eventarc(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid = ctx.project_id
    dest = d.get("destination") or {}
    run = dest.get("cloudRun") or {}
    if run.get("service") and pid:
        region = run.get("region") or ctx.location
        out.add(
            f"//run.googleapis.com/projects/{pid}/locations/{region}/services/{run['service']}",
            EdgeType.INVOKES,
            "INVOKES",
        )
    out.add(full_name(dest.get("workflow"), "workflows"), EdgeType.INVOKES, "INVOKES")
    out.add(full_name(dest.get("cloudFunction"), "cloudfunctions"), EdgeType.INVOKES, "INVOKES")
    gke = dest.get("gke") or {}
    if gke.get("cluster") and pid:
        out.add(
            f"//container.googleapis.com/projects/{pid}/locations/{gke.get('location')}/clusters/{gke['cluster']}",
            EdgeType.INVOKES,
            "INVOKES",
            namespace=gke.get("namespace"),
            service=gke.get("service"),
        )
    out.sa(d.get("serviceAccount"), ctx, "trigger identity")
    pubsub = dig(d, "transport", "pubsub", default={}) or {}
    out.add(
        full_name(pubsub.get("topic"), "pubsub"), EdgeType.INVOKES, "TRIGGERED_BY", reverse=True
    )
    out.add(full_name(pubsub.get("subscription"), "pubsub"), EdgeType.REFERENCES, "DEPENDS_ON")
    filters = {}
    for f in _list(d.get("eventFilters")):
        if isinstance(f, dict) and f.get("attribute"):
            filters[f["attribute"]] = f.get("value")
    if filters.get("bucket"):
        out.add(
            f"//storage.googleapis.com/{filters['bucket']}",
            EdgeType.INVOKES,
            "TRIGGERED_BY",
            reverse=True,
        )
    out.metadata.update(
        event_filters=filters,
        channel=d.get("channel"),
        http_destination=url_alias(dig(dest, "httpEndpoint", "uri")),
    )
