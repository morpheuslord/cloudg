"""Data processing, ML and CI/CD."""

from __future__ import annotations

from cloudg.inventory.gcp_relations.names import (
    _list,
    dig,
    full_name,
    image_repository,
    network_ref,
    subnet_ref,
    url_alias,
)
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Data processing, ML, CI/CD
# ---------------------------------------------------------------------------


@_extractor("composer.googleapis.com/Environment")
def _composer(ctx: GCPContext, out: Extracted) -> None:
    cfg = ctx.data.get("config") or {}
    nc = cfg.get("nodeConfig") or {}
    out.sa(nc.get("serviceAccount") or "default", ctx, "Composer worker identity")
    out.in_subnet(
        full_name(nc.get("subnetwork"), "compute") or full_name(nc.get("network"), "compute")
    )
    out.add(full_name(cfg.get("gkeCluster"), "container"), EdgeType.MANAGES, "OWNED_BY")
    prefix = cfg.get("dagGcsPrefix")
    out.add(full_name(prefix), EdgeType.REFERENCES, "READS_FROM", description="DAG bucket")
    out.metadata.update(
        private_environment=bool(dig(cfg, "privateEnvironmentConfig", "enablePrivateEnvironment")),
        airflow_uri=url_alias(cfg.get("airflowUri")),
        image_version=dig(cfg, "softwareConfig", "imageVersion"),
    )


@_extractor("dataproc.googleapis.com/Cluster")
def _dataproc(ctx: GCPContext, out: Extracted) -> None:
    cfg = ctx.data.get("config") or {}
    gce = cfg.get("gceClusterConfig") or {}
    out.sa(gce.get("serviceAccount") or "default", ctx, "Dataproc VM identity")
    out.in_subnet(
        full_name(gce.get("subnetworkUri"), "compute")
        or network_ref(gce.get("networkUri"), ctx.project_id)
    )
    for key in ("configBucket", "tempBucket"):
        if cfg.get(key):
            out.add(f"//storage.googleapis.com/{cfg[key]}", EdgeType.REFERENCES, "WRITES_TO")
    out.metadata.update(
        internal_ip_only=gce.get("internalIpOnly"), network_tags=list(gce.get("tags") or [])
    )


@_extractor("dataflow.googleapis.com/Job")
def _dataflow(ctx: GCPContext, out: Extracted) -> None:
    env = ctx.data.get("environment") or {}
    out.sa(env.get("serviceAccountEmail") or "default", ctx, "Dataflow worker identity")
    for wp in _list(env.get("workerPools")):
        if isinstance(wp, dict):
            out.in_subnet(
                subnet_ref(wp.get("subnetwork"), ctx.project_id, ctx.region)
                or network_ref(wp.get("network"), ctx.project_id)
            )
    out.add(full_name(env.get("tempStoragePrefix")), EdgeType.REFERENCES, "WRITES_TO")
    out.metadata.update(job_type=ctx.data.get("type"), current_state=ctx.data.get("currentState"))


@_extractor("aiplatform.googleapis.com/Endpoint")
def _vertex_endpoint(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for dm in _list(d.get("deployedModels")):
        if isinstance(dm, dict):
            out.add(
                full_name(dm.get("model"), "aiplatform"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="deployed model",
            )
            out.sa(dm.get("serviceAccount"), ctx, "model serving identity")
    out.add(full_name(d.get("network"), "compute"), EdgeType.ATTACHED_TO)
    if not d.get("network") and not dig(
        d, "privateServiceConnectConfig", "enablePrivateServiceConnect"
    ):
        out.metadata["public_endpoint"] = True


@_extractor("aiplatform.googleapis.com/Model")
def _vertex_model(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(image_repository(dig(d, "containerSpec", "imageUri")), EdgeType.USES_IMAGE, "RUNS_ON")
    out.add(full_name(d.get("artifactUri")), EdgeType.REFERENCES, "READS_FROM")


@_extractor("notebooks.googleapis.com/Instance", "notebooks.googleapis.com/Runtime")
def _workbench(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    gce = d.get("gceSetup") or {}
    vm = dig(d, "virtualMachine", "virtualMachineConfig", default={}) or {}
    out.sa(d.get("serviceAccount"), ctx, "notebook identity")
    for sa in _list(gce.get("serviceAccounts")):
        if isinstance(sa, dict):
            out.sa(sa.get("email"), ctx, "notebook identity")
    nets = [(d.get("subnet"), d.get("network")), (vm.get("subnet"), vm.get("network"))]
    nets += [
        (n.get("subnet"), n.get("network"))
        for n in _list(gce.get("networkInterfaces"))
        if isinstance(n, dict)
    ]
    for sub, net in nets:
        out.in_subnet(full_name(sub, "compute") or full_name(net, "compute"))
    out.metadata["public_ip_disabled"] = bool(
        d.get("noPublicIp") or gce.get("disablePublicIp") or vm.get("internalIpOnly")
    )


@_extractor("cloudbuild.googleapis.com/BuildTrigger")
def _build_trigger(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.sa(
        d.get("serviceAccount")
        or (f"{ctx.project_number}@cloudbuild.gserviceaccount.com" if ctx.project_number else None),
        ctx,
        "build identity",
    )
    out.add(
        full_name(dig(d, "pubsubConfig", "topic"), "pubsub"),
        EdgeType.INVOKES,
        "TRIGGERED_BY",
        reverse=True,
    )
    gh = d.get("github") or {}
    out.metadata.update(
        repository=f"{gh.get('owner')}/{gh.get('name')}"
        if gh.get("name")
        else dig(d, "sourceToBuild", "uri") or dig(d, "repositoryEventConfig", "repository"),
        filename=d.get("filename"),
        disabled=bool(d.get("disabled")),
    )


@_extractor("clouddeploy.googleapis.com/DeliveryPipeline")
def _deploy_pipeline(ctx: GCPContext, out: Extracted) -> None:
    base = ctx.name.split("/deliveryPipelines/", 1)[0]
    for stage in _list(dig(ctx.data, "serialPipeline", "stages")):
        if isinstance(stage, dict) and stage.get("targetId"):
            out.add(
                f"{base}/targets/{stage['targetId']}",
                EdgeType.MANAGES,
                "DEPENDS_ON",
                description="pipeline stage",
            )


@_extractor("clouddeploy.googleapis.com/Target")
def _deploy_target(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(dig(d, "gke", "cluster"), "container"), EdgeType.MANAGES, "OWNED_BY")
    for ec in _list(d.get("executionConfigs")):
        if isinstance(ec, dict):
            out.sa(ec.get("serviceAccount"), ctx, "deploy execution identity")
    out.metadata.update(
        require_approval=bool(d.get("requireApproval")), run_location=dig(d, "run", "location")
    )
