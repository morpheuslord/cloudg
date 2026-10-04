"""GKE clusters, node pools and Kubernetes objects."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    INTERNET_CIDRS,
    K8S_GKE_PREFIX,
    _list,
    _num,
    dig,
    full_name,
    image_repository,
    network_ref,
    sa_ref,
    subnet_ref,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# GKE and Kubernetes
# ---------------------------------------------------------------------------


@_extractor("container.googleapis.com/Cluster")
def _gke_cluster(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    nc = d.get("networkConfig") or {}
    pid = ctx.project_id
    net = full_name(nc.get("network"), "compute") or network_ref(d.get("network"), pid)
    sub = full_name(nc.get("subnetwork"), "compute") or subnet_ref(
        d.get("subnetwork"), pid, ctx.region
    )
    out.in_subnet(sub or net)
    out.sa(dig(d, "nodeConfig", "serviceAccount"), ctx, "node service account")
    out.sa(
        dig(d, "autoscaling", "autoprovisioningNodePoolDefaults", "serviceAccount"),
        ctx,
        "autoprovisioned node service account",
    )
    pcc = d.get("privateClusterConfig") or {}
    man = d.get("masterAuthorizedNetworksConfig") or {}
    ip_ep = dig(d, "controlPlaneEndpointsConfig", "ipEndpointsConfig", default={}) or {}
    if ip_ep:
        public_endpoint = bool(
            ip_ep.get("enablePublicEndpoint", not pcc.get("enablePrivateEndpoint"))
        )
        man = ip_ep.get("authorizedNetworksConfig") or man
    else:
        public_endpoint = not pcc.get("enablePrivateEndpoint")
    cidrs = [c.get("cidrBlock") for c in _list(man.get("cidrBlocks")) if isinstance(c, dict)]
    authorized = bool(man.get("enabled"))
    if public_endpoint and (not authorized or any(c in INTERNET_CIDRS for c in cidrs)):
        out.expose("public GKE control plane endpoint", protocol="tcp", ports=["443"])
    db_enc = d.get("databaseEncryption") or {}
    out.metadata.update(
        network=net,
        subnetwork=sub,
        endpoint=d.get("endpoint"),
        public_endpoint=public_endpoint,
        private_nodes=bool(pcc.get("enablePrivateNodes")),
        master_authorized_networks_enabled=authorized,
        master_authorized_networks=cidrs,
        workload_pool=dig(d, "workloadIdentityConfig", "workloadPool"),
        secrets_encryption=db_enc.get("state"),
        autopilot=bool(dig(d, "autopilot", "enabled")),
        current_master_version=d.get("currentMasterVersion"),
        release_channel=dig(d, "releaseChannel", "channel"),
        legacy_abac=bool(dig(d, "legacyAbac", "enabled")),
        network_policy=bool(dig(d, "networkPolicy", "enabled")),
        binary_authorization=dig(d, "binaryAuthorization", "evaluationMode")
        or dig(d, "binaryAuthorization", "enabled"),
        shielded_nodes=bool(dig(d, "shieldedNodes", "enabled")),
    )


@_extractor("container.googleapis.com/NodePool")
def _node_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    cluster = ctx.name.split("/nodePools/", 1)[0]
    out.add(cluster, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True)
    out.sa(dig(d, "config", "serviceAccount"), ctx, "node pool service account")
    for url in _list(d.get("instanceGroupUrls")):
        out.add(full_name(url, "compute"), EdgeType.MANAGES, "SCALES_WITH")
    out.metadata.update(
        machine_type=dig(d, "config", "machineType"),
        image_type=dig(d, "config", "imageType"),
        workload_metadata_mode=dig(d, "config", "workloadMetadataConfig", "mode"),
        autoscaling=bool(dig(d, "autoscaling", "enabled")),
        node_count=_num(d.get("initialNodeCount")),
        network_tags=list(dig(d, "config", "tags", default=[]) or []),
    )


def _cluster_of_k8s(name: str) -> str:
    return name.split("/k8s/", 1)[0]


def _pod_spec(d: dict[str, Any]) -> dict[str, Any]:
    spec = d.get("spec") or {}
    return (
        dig(spec, "jobTemplate", "spec", "template", "spec")
        or dig(spec, "template", "spec")
        or spec
    )


@_extractor(
    "apps.k8s.io/Deployment",
    "apps.k8s.io/StatefulSet",
    "apps.k8s.io/DaemonSet",
    "batch.k8s.io/CronJob",
    "batch.k8s.io/Job",
    "k8s.io/Pod",
)
def _k8s_workload(ctx: GCPContext, out: Extracted) -> None:
    pod = _pod_spec(ctx.data)
    images = []
    for c in _list(pod.get("containers")) + _list(pod.get("initContainers")):
        if isinstance(c, dict) and c.get("image"):
            images.append(c["image"])
            out.add(image_repository(c["image"]), EdgeType.USES_IMAGE, "RUNS_ON")
    out.metadata.update(
        namespace=dig(ctx.data, "metadata", "namespace"),
        images=images,
        kubernetes_service_account=pod.get("serviceAccountName"),
        host_network=bool(pod.get("hostNetwork")),
        privileged=any(
            dig(c, "securityContext", "privileged")
            for c in _list(pod.get("containers"))
            if isinstance(c, dict)
        ),
    )


@_extractor("k8s.io/Service")
def _k8s_service(ctx: GCPContext, out: Extracted) -> None:
    spec = ctx.data.get("spec") or {}
    ann = dig(ctx.data, "metadata", "annotations", default={}) or {}
    internal = any(
        str(ann.get(k, "")).lower() == "internal"
        for k in ("networking.gke.io/load-balancer-type", "cloud.google.com/load-balancer-type")
    )
    stype = spec.get("type")
    ips = [
        i.get("ip")
        for i in _list(dig(ctx.data, "status", "loadBalancer", "ingress"))
        if isinstance(i, dict)
    ]
    if stype == "LoadBalancer" and not internal:
        ranges = spec.get("loadBalancerSourceRanges") or []
        if not ranges or any(r in INTERNET_CIDRS for r in ranges):
            ports = [_num(p.get("port")) for p in _list(spec.get("ports")) if isinstance(p, dict)]
            out.expose("Kubernetes LoadBalancer service", ports=ports)
    for ip in ips:
        if ip and not internal:
            out.alias(ip)
    out.metadata.update(
        service_type=stype, namespace=dig(ctx.data, "metadata", "namespace"), load_balancer_ips=ips
    )


@_extractor("networking.k8s.io/Ingress", "extensions.k8s.io/Ingress")
def _k8s_ingress(ctx: GCPContext, out: Extracted) -> None:
    ann = dig(ctx.data, "metadata", "annotations", default={}) or {}
    klass = (
        ann.get("kubernetes.io/ingress.class") or dig(ctx.data, "spec", "ingressClassName") or "gce"
    )
    hosts = [
        r.get("host")
        for r in _list(dig(ctx.data, "spec", "rules"))
        if isinstance(r, dict) and r.get("host")
    ]
    if klass in ("gce", "gce-multi-cluster"):
        out.expose(f"Kubernetes ingress ({klass})", protocol="tcp", ports=["80", "443"])
    out.metadata.update(
        ingress_class=klass, hosts=hosts, namespace=dig(ctx.data, "metadata", "namespace")
    )


@_extractor("k8s.io/ServiceAccount")
def _k8s_sa(ctx: GCPContext, out: Extracted) -> None:
    meta = ctx.data.get("metadata") or {}
    ns, name = meta.get("namespace"), meta.get("name")
    gsa = (meta.get("annotations") or {}).get("iam.gke.io/gcp-service-account")
    if gsa:
        out.add(
            sa_ref(gsa),
            EdgeType.ASSUMES_ROLE,
            "ROLE_ASSUMES_ROLE",
            description="GKE workload identity",
        )
    if ctx.project_id and ns and name:
        out.alias(f"{K8S_GKE_PREFIX}{ctx.project_id}/{ns}/{name}")
    out.metadata.update(namespace=ns, gcp_service_account=gsa)


@_extractor(
    "rbac.authorization.k8s.io/ClusterRoleBinding",
    "rbac.authorization.k8s.io/RoleBinding",
)
def _k8s_binding(ctx: GCPContext, out: Extracted) -> None:
    subjects = [
        f"{s.get('kind')}:{(s.get('namespace') + '/') if s.get('namespace') else ''}{s.get('name')}"
        for s in _list(ctx.data.get("subjects"))
        if isinstance(s, dict)
    ]
    ref = ctx.data.get("roleRef") or {}
    out.metadata.update(subjects=subjects[:100], role_ref=f"{ref.get('kind')}:{ref.get('name')}")
