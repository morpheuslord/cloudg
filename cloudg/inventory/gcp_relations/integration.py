"""Integration: Cloud Scheduler, Eventarc channels and Eventarc Advanced,
Managed Kafka topics and Connect, Pub/Sub snapshots and schemas, the calls
inside Workflows definitions, and Batch jobs."""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.gcp_relations._refs import (
    bq_ref,
    gcs_ref,
    parent_of,
    url_target,
)
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    _list,
    _num,
    dig,
    full_name,
    image_repository,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Cloud Scheduler
# ---------------------------------------------------------------------------


@_extractor("cloudscheduler.googleapis.com/Job")
def _scheduler_job(ctx: GCPContext, out: Extracted) -> None:
    """A scheduler job runs its target on a schedule (INVOKES / SCHEDULED_BY)."""
    d = ctx.data
    http = d.get("httpTarget") or {}
    out.add(
        url_target(http.get("uri")),
        EdgeType.INVOKES,
        "SCHEDULED_BY",
        description="scheduled HTTP target",
        http_method=http.get("httpMethod"),
    )
    out.sa(
        dig(http, "oidcToken", "serviceAccountEmail")
        or dig(http, "oauthToken", "serviceAccountEmail"),
        ctx,
        "scheduler job identity",
    )
    out.add(
        full_name(dig(d, "pubsubTarget", "topicName"), "pubsub"),
        EdgeType.INVOKES,
        "SCHEDULED_BY",
        description="scheduled Pub/Sub message",
    )
    ae = d.get("appEngineHttpTarget") or {}
    service = dig(ae, "appEngineRouting", "service") or ("default" if ae else None)
    if service and ctx.project_id:
        out.add(
            f"//appengine.googleapis.com/apps/{ctx.project_id}/services/{service}",
            EdgeType.INVOKES,
            "SCHEDULED_BY",
            description="scheduled App Engine request",
        )
    out.metadata.update(
        schedule=d.get("schedule"),
        time_zone=d.get("timeZone"),
        target_type="http" if http else "pubsub" if d.get("pubsubTarget") else "appengine",
        target=url_target(http.get("uri")),
        attempt_deadline=d.get("attemptDeadline"),
        retry_count=_num(dig(d, "retryConfig", "retryCount")),
    )


# ---------------------------------------------------------------------------
# Eventarc
# ---------------------------------------------------------------------------


@_extractor("eventarc.googleapis.com/Channel")
def _eventarc_channel(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("pubsubTopic"), "pubsub"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="channel transport topic",
    )
    out.metadata.update(provider=d.get("provider"), channel_state=d.get("state"))


@_extractor("eventarc.googleapis.com/ChannelConnection")
def _eventarc_channel_connection(ctx: GCPContext, out: Extracted) -> None:
    out.add(full_name(ctx.data.get("channel"), "eventarc"), EdgeType.REFERENCES, "DEPENDS_ON")


@_extractor("eventarc.googleapis.com/Trigger")
def _eventarc_trigger_channel(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("channel"), "eventarc"),
        EdgeType.INVOKES,
        "TRIGGERED_BY",
        reverse=True,
        description="third-party channel events",
    )


@_extractor("eventarc.googleapis.com/GoogleApiSource")
def _eventarc_api_source(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("destination"), "eventarc"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="Google API events to the message bus",
    )


@_extractor("eventarc.googleapis.com/Enrollment")
def _eventarc_enrollment(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("messageBus"), "eventarc"),
        EdgeType.INVOKES,
        "TRIGGERED_BY",
        reverse=True,
        description="message bus delivers matching events",
    )
    out.add(full_name(d.get("destination"), "eventarc"), EdgeType.INVOKES, "INVOKES")
    out.metadata["cel_match"] = d.get("celMatch")


@_extractor("eventarc.googleapis.com/Pipeline")
def _eventarc_pipeline(ctx: GCPContext, out: Extracted) -> None:
    for dest in _list(ctx.data.get("destinations")):
        if not isinstance(dest, dict):
            continue
        out.add(full_name(dest.get("workflow"), "workflows"), EdgeType.INVOKES, "INVOKES")
        out.add(full_name(dest.get("messageBus"), "eventarc"), EdgeType.INVOKES, "STREAMS_TO")
        out.add(full_name(dest.get("topic"), "pubsub"), EdgeType.INVOKES, "STREAMS_TO")
        out.add(url_target(dig(dest, "httpEndpoint", "uri")), EdgeType.INVOKES, "INVOKES")
        auth = dest.get("authenticationConfig") or {}
        out.sa(
            dig(auth, "googleOidc", "serviceAccount") or dig(auth, "oauthToken", "serviceAccount"),
            ctx,
            "pipeline delivery identity",
        )


@_extractor("eventarc.googleapis.com/MessageBus")
def _eventarc_bus(ctx: GCPContext, out: Extracted) -> None:
    out.metadata["log_severity"] = dig(ctx.data, "loggingConfig", "logSeverity")


# ---------------------------------------------------------------------------
# Managed Service for Apache Kafka
# ---------------------------------------------------------------------------


@_extractor("managedkafka.googleapis.com/Topic")
def _kafka_topic(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "topics"), EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        partition_count=_num(d.get("partitionCount")),
        replication_factor=_num(d.get("replicationFactor")),
    )


@_extractor("managedkafka.googleapis.com/ConsumerGroup")
def _kafka_consumer_group(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "consumerGroups"), EdgeType.CONTAINS, reverse=True)
    cluster = parent_of(ctx.name, "consumerGroups")
    for topic in (ctx.data.get("topics") or {}).keys():
        ref = full_name(topic, "managedkafka") if "/" in str(topic) else None
        if not ref and cluster:
            ref = f"{cluster}/topics/{topic}"
        out.add(ref, EdgeType.REFERENCES, "READS_FROM", description="consumer group offsets")


@_extractor("managedkafka.googleapis.com/ConnectCluster")
def _kafka_connect_cluster(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("kafkaCluster"), "managedkafka"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
        description="Kafka cluster the connectors use",
    )
    for nc in _list(dig(d, "gcpConfig", "accessConfig", "networkConfigs")):
        if isinstance(nc, dict):
            out.in_subnet(full_name(nc.get("primarySubnet"), "compute"))


def _connector_targets(cfg: dict[str, Any], project: str | None) -> list[tuple[str | None, str]]:
    """(target, relation) pairs a Kafka Connect connector's config names."""
    cls = str(cfg.get("connector.class") or "")
    sink = "Sink" in cls
    verb = "STREAMS_TO" if sink else "READS_FROM"
    targets: list[tuple[str | None, str]] = []
    if cfg.get("cps.topic"):
        targets.append(
            (
                f"//pubsub.googleapis.com/projects/{cfg.get('cps.project') or project}/topics/{cfg['cps.topic']}",
                verb,
            )
        )
    if cfg.get("gcs.bucket.name"):
        targets.append((gcs_ref(cfg["gcs.bucket.name"]), verb))
    if cfg.get("defaultDataset"):
        targets.append((bq_ref(f"{cfg.get('project') or project}.{cfg['defaultDataset']}"), verb))
    return targets


@_extractor("managedkafka.googleapis.com/Connector")
def _kafka_connector(ctx: GCPContext, out: Extracted) -> None:
    cfg = ctx.data.get("configs") or {}
    out.add(parent_of(ctx.name, "connectors"), EdgeType.CONTAINS, reverse=True)
    for target, verb in _connector_targets(cfg, ctx.project_id):
        edge = EdgeType.INVOKES if verb == "STREAMS_TO" else EdgeType.REFERENCES
        out.add(target, edge, verb, description="Kafka Connect connector")
    out.metadata["connector_class"] = cfg.get("connector.class")


# ---------------------------------------------------------------------------
# Pub/Sub snapshots and schemas
# ---------------------------------------------------------------------------


@_extractor("pubsub.googleapis.com/Snapshot")
def _pubsub_snapshot(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("topic"), "pubsub"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["expire_time"] = d.get("expireTime")


@_extractor("pubsub.googleapis.com/Schema")
def _pubsub_schema(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(schema_type=d.get("type"), revision_id=d.get("revisionId"))


# ---------------------------------------------------------------------------
# Workflows: what a definition calls
# ---------------------------------------------------------------------------

_CALL_RE = re.compile(r"^\s*(?:-\s*)?call:\s*([A-Za-z0-9_.]+)")
_LIT = r"[A-Za-z0-9_.-]+"
_RES_RE = re.compile(
    rf"(projects/{_LIT}/(?:locations/{_LIT}/)?"
    r"(topics|subscriptions|secrets|workflows|functions|services|jobs|datasets|queues)"
    rf"/{_LIT})"
)
_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(?:/[^\s\"'$}]*)?")
_BUCKET_RE = re.compile(rf"^\s*bucket:\s*[\"']?({_LIT})[\"']?\s*$")
_WRITE_VERBS = ("publish", "insert", "create", "write", "patch", "update", "put", "upload", "add")
_SERVICES = {
    "topics": "pubsub",
    "subscriptions": "pubsub",
    "secrets": "secretmanager",
    "workflows": "workflows",
    "functions": "cloudfunctions",
    "services": "run",
    "jobs": "run",
    "datasets": "bigquery",
    "queues": "cloudtasks",
}
_COMPUTE = {"workflows", "functions", "services", "jobs"}
_MAX_SOURCE = 256 * 1024


def _call_verb(call: str | None) -> str:
    method = (call or "").rsplit(".", 1)[-1].lower()
    return "WRITES_TO" if any(v in method for v in _WRITE_VERBS) else "READS_FROM"


def workflow_calls(source: str) -> list[tuple[str, EdgeType, str]]:
    """(target, edge, relation) for each literal resource / URL a definition calls."""
    found: list[tuple[str, EdgeType, str]] = []
    call: str | None = None
    for line in source[:_MAX_SOURCE].splitlines():
        m = _CALL_RE.match(line)
        if m:
            call = m.group(1)
        for ref, collection in _RES_RE.findall(line):
            target = full_name(ref, _SERVICES[collection])
            if collection in _COMPUTE:
                found.append((target, EdgeType.INVOKES, "INVOKES"))
            elif collection == "secrets":
                found.append(
                    (
                        full_name(ref.split("/versions/")[0], "secretmanager"),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                    )
                )
            else:
                found.append((target, EdgeType.REFERENCES, _call_verb(call)))
        if call and call.startswith("http"):
            for url in _URL_RE.findall(line):
                found.append((url_target(url), EdgeType.INVOKES, "INVOKES"))
        m = _BUCKET_RE.match(line)
        if m and call and ".storage." in f".{call}.":
            found.append((gcs_ref(m.group(1)), EdgeType.REFERENCES, _call_verb(call)))
    return [(t, e, r) for t, e, r in dict.fromkeys(found) if t]


@_extractor("workflows.googleapis.com/Workflow")
def _workflow_definition(ctx: GCPContext, out: Extracted) -> None:
    source = ctx.data.get("sourceContents")
    if not isinstance(source, str) or not source:
        return
    connectors = sorted(
        {
            m.group(1).rsplit(".", 1)[0]
            for m in map(_CALL_RE.match, source.splitlines())
            if m and m.group(1).startswith("googleapis.")
        }
    )
    for target, edge, relation in workflow_calls(source):
        out.add(target, edge, relation, description="called from the workflow definition")
    out.metadata["connectors"] = connectors


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------


@_extractor("batch.googleapis.com/Job")
def _batch_job(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    alloc = d.get("allocationPolicy") or {}
    out.sa(dig(alloc, "serviceAccount", "email") or "default", ctx, "Batch VM identity")
    no_external = True
    for ni in _list(dig(alloc, "network", "networkInterfaces")):
        if isinstance(ni, dict):
            out.in_subnet(full_name(ni.get("subnetwork") or ni.get("network"), "compute"))
            no_external = no_external and bool(ni.get("noExternalIpAddress"))
    for inst in _list(alloc.get("instances")):
        if isinstance(inst, dict):
            out.add(
                full_name(inst.get("instanceTemplate"), "compute"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
            )
    images = []
    for group in _list(d.get("taskGroups")):
        spec = (group.get("taskSpec") or {}) if isinstance(group, dict) else {}
        for runnable in _list(spec.get("runnables")):
            image = dig(runnable, "container", "imageUri") if isinstance(runnable, dict) else None
            if image:
                images.append(image)
                out.add(image_repository(image), EdgeType.USES_IMAGE, "RUNS_ON")
        for vol in _list(spec.get("volumes")):
            path = dig(vol, "gcs", "remotePath") if isinstance(vol, dict) else None
            if path:
                bucket = str(path).removeprefix("gs://").split("/", 1)[0]
                out.add(
                    gcs_ref(bucket), EdgeType.REFERENCES, "READS_FROM", description="mounted bucket"
                )
    for note in _list(d.get("notifications")):
        if isinstance(note, dict):
            out.add(full_name(note.get("pubsubTopic"), "pubsub"), EdgeType.INVOKES, "INVOKES")
    out.metadata.update(
        images=images,
        job_state=dig(d, "status", "state"),
        logs_destination=dig(d, "logsPolicy", "destination"),
        no_external_ip=no_external if alloc.get("network") else None,
    )
