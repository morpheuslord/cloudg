"""Read-only Kubernetes workload mapping for EKS clusters.

Authenticates exactly like ``aws eks get-token``: a presigned STS
``GetCallerIdentity`` URL carrying the ``x-k8s-aws-id`` header, sent as a
bearer token. Only ``GET`` requests are issued, TLS is verified against
the cluster's own CA, and no Kubernetes client library is needed.

The identity cloudg runs as must be able to reach the API endpoint and
hold read access in the cluster (an EKS access entry with
``AmazonEKSViewPolicy`` is enough; secrets are never read).

Mapped objects and relationships:

- Namespaces (cluster CONTAINS namespace CONTAINS objects)
- Deployments, StatefulSets, DaemonSets, CronJobs -> container images
  (USES_IMAGE, resolved to ECR repositories) and service accounts
- Services -> the workloads their selector matches (LOAD_BALANCER_TARGET);
  ``LoadBalancer`` services -> the AWS load balancer by DNS name (ROUTE)
- Ingresses -> backend services, and -> the ALB by DNS name
- ServiceAccounts -> IAM roles through the IRSA annotation (ASSUMES_ROLE)
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import urllib.parse
import urllib.request
from typing import Any, Iterator

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.containers import image_repository, k8s_identifier
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

_WORKLOAD_KINDS = {
    "Deployment": "/apis/apps/v1/deployments",
    "StatefulSet": "/apis/apps/v1/statefulsets",
    "DaemonSet": "/apis/apps/v1/daemonsets",
    "CronJob": "/apis/batch/v1/cronjobs",
}
_IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
_PAGE_LIMIT = 500
_MAX_OBJECTS = 5000


def eks_token(session: Any, cluster_name: str, region: str) -> str:
    """Bearer token for the EKS Kubernetes API (same as ``aws eks get-token``)."""
    from botocore.signers import RequestSigner

    sts = session.client("sts", region_name=region)
    signer = RequestSigner(
        sts.meta.service_model.service_id,
        region,
        "sts",
        "v4",
        session.get_credentials(),
        session.events if hasattr(session, "events") else sts.meta.events,
    )
    params = {
        "method": "GET",
        "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    url = signer.generate_presigned_url(
        params, region_name=region, expires_in=60, operation_name=""
    )
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
    return f"k8s-aws-v1.{encoded}"


class KubernetesReader:
    """Minimal read-only Kubernetes API client."""

    def __init__(self, endpoint: str, ca_data_b64: str | None, token: str, timeout: int = 10):
        self._endpoint = endpoint.rstrip("/")
        self._token = token
        self._timeout = timeout
        if ca_data_b64:
            pem = base64.b64decode(ca_data_b64).decode("utf-8")
            self._ssl = ssl.create_default_context(cadata=pem)
        else:
            self._ssl = ssl.create_default_context()

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self._endpoint + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        if not url.startswith("https://"):
            raise ValueError("Kubernetes endpoint must be https")
        req = urllib.request.Request(  # nosec B310 - https enforced above
            url,
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl) as resp:  # nosec B310
            return json.loads(resp.read().decode("utf-8"))

    def list(self, path: str) -> Iterator[dict[str, Any]]:
        """All items of a list endpoint, following ``continue`` tokens."""
        params: dict[str, Any] = {"limit": _PAGE_LIMIT}
        seen = 0
        while True:
            data = self.get(path, params)
            for item in data.get("items", []) or []:
                seen += 1
                if seen > _MAX_OBJECTS:
                    logger.warning("Kubernetes listing %s truncated at %d objects", path, _MAX_OBJECTS)
                    return
                yield item
            token = (data.get("metadata") or {}).get("continue")
            if not token:
                return
            params = {"limit": _PAGE_LIMIT, "continue": token}


def _pod_spec(kind: str, obj: dict[str, Any]) -> dict[str, Any]:
    spec = obj.get("spec") or {}
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def _pod_labels(kind: str, obj: dict[str, Any]) -> dict[str, str]:
    spec = obj.get("spec") or {}
    if kind == "CronJob":
        tmpl = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        tmpl = spec.get("template") or {}
    return (tmpl.get("metadata") or {}).get("labels") or {}


def _lb_hostnames(obj: dict[str, Any]) -> list[str]:
    ingress = ((obj.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []
    return [i.get("hostname") for i in ingress if i.get("hostname")]


def map_cluster_objects(
    reader: KubernetesReader,
    cluster_arn: str,
    region: str,
    account_id: str | None,
) -> list[CloudAsset]:
    """Read namespaces, workloads, services, ingresses and service accounts."""

    def asset(
        kind: str,
        namespace: str,
        name: str,
        asset_type: AssetType,
        metadata: dict[str, Any],
        relations: list[dict | None],
        labels: dict[str, str] | None = None,
        exposed: bool = False,
    ) -> CloudAsset:
        md = {"cluster_arn": cluster_arn, "namespace": namespace, "kind": kind, **metadata}
        rels = [r for r in relations if r]
        if rels:
            md["relations"] = rels
        return CloudAsset(
            arn=k8s_identifier(cluster_arn, namespace, kind, name),
            name=f"{namespace}/{name}" if namespace else name,
            asset_type=asset_type,
            provider=CloudProvider.AWS,
            region=region,
            account_id=account_id,
            tags={k: str(v) for k, v in (labels or {}).items()},
            metadata=md,
            is_internet_exposed=exposed,
        )

    assets: list[CloudAsset] = []

    for ns in reader.list("/api/v1/namespaces"):
        name = ns["metadata"]["name"]
        assets.append(
            asset(
                "Namespace",
                "",
                name,
                AssetType.K8S_NAMESPACE,
                {"phase": (ns.get("status") or {}).get("phase")},
                [rel(cluster_arn, EdgeType.CONTAINS, "CLUSTER_CONTAINS_SERVICE", reverse=True)],
                labels=ns["metadata"].get("labels"),
            )
        )

    def ns_rel(namespace: str) -> dict | None:
        return rel(
            k8s_identifier(cluster_arn, "", "Namespace", namespace),
            EdgeType.CONTAINS,
            "CLUSTER_CONTAINS_SERVICE",
            reverse=True,
        )

    for sa in reader.list("/api/v1/serviceaccounts"):
        meta = sa["metadata"]
        role = (meta.get("annotations") or {}).get(_IRSA_ANNOTATION)
        assets.append(
            asset(
                "ServiceAccount",
                meta.get("namespace", ""),
                meta["name"],
                AssetType.K8S_SERVICE_ACCOUNT,
                {"irsa_role_arn": role},
                [
                    ns_rel(meta.get("namespace", "")),
                    rel(role, EdgeType.ASSUMES_ROLE, "RUNS_ON", description="IRSA"),
                ],
            )
        )

    workloads: list[tuple[str, str, str, dict[str, str]]] = []  # ns, kind, name, pod labels
    for kind, path in _WORKLOAD_KINDS.items():
        try:
            items = list(reader.list(path))
        except Exception as exc:
            logger.debug("Kubernetes %s listing failed: %s", kind, exc)
            continue
        for obj in items:
            meta = obj["metadata"]
            ns = meta.get("namespace", "")
            pod = _pod_spec(kind, obj)
            containers = (pod.get("containers") or []) + (pod.get("initContainers") or [])
            images = [c.get("image", "") for c in containers if c.get("image")]
            sa_name = pod.get("serviceAccountName") or pod.get("serviceAccount") or "default"
            labels = _pod_labels(kind, obj)
            workloads.append((ns, kind, meta["name"], labels))
            relations: list[dict | None] = [ns_rel(ns)]
            relations += [
                rel(image_repository(img), EdgeType.USES_IMAGE, "RUNS_ON", description=f"runs {img}")
                for img in dict.fromkeys(images)
            ]
            relations.append(
                rel(k8s_identifier(cluster_arn, ns, "ServiceAccount", sa_name), EdgeType.REFERENCES, "RUNS_ON", description="runs as service account")
            )
            spec = obj.get("spec") or {}
            status = obj.get("status") or {}
            assets.append(
                asset(
                    kind,
                    ns,
                    meta["name"],
                    AssetType.K8S_WORKLOAD,
                    {
                        "replicas": spec.get("replicas"),
                        "ready_replicas": status.get("readyReplicas"),
                        "schedule": spec.get("schedule"),
                        "images": images,
                        "service_account": sa_name,
                        "host_network": bool(pod.get("hostNetwork")),
                        "privileged_containers": [
                            c.get("name") for c in containers
                            if (c.get("securityContext") or {}).get("privileged")
                        ],
                        "node_selector": pod.get("nodeSelector") or {},
                    },
                    relations,
                    labels=meta.get("labels"),
                )
            )

    for svc in reader.list("/api/v1/services"):
        meta = svc["metadata"]
        ns = meta.get("namespace", "")
        spec = svc.get("spec") or {}
        selector = spec.get("selector") or {}
        relations = [ns_rel(ns)]
        if selector:
            for w_ns, w_kind, w_name, w_labels in workloads:
                if w_ns == ns and all(w_labels.get(k) == v for k, v in selector.items()):
                    relations.append(
                        rel(k8s_identifier(cluster_arn, w_ns, w_kind, w_name), EdgeType.LOAD_BALANCER_TARGET, "SERVES_TRAFFIC_TO")
                    )
        hostnames = _lb_hostnames(svc)
        for host in hostnames:
            relations.append(rel(host, EdgeType.ROUTE, "LOAD_BALANCED_BY", reverse=True, description="cloud load balancer"))
        svc_type = spec.get("type", "ClusterIP")
        assets.append(
            asset(
                "Service",
                ns,
                meta["name"],
                AssetType.K8S_SERVICE,
                {
                    "service_type": svc_type,
                    "ports": [p.get("port") for p in spec.get("ports", []) or []],
                    "load_balancer_hostnames": hostnames,
                    "internal": (meta.get("annotations") or {}).get("service.beta.kubernetes.io/aws-load-balancer-scheme") == "internal",
                },
                relations,
                labels=meta.get("labels"),
                exposed=svc_type == "LoadBalancer" and bool(hostnames),
            )
        )

    try:
        ingresses = list(reader.list("/apis/networking.k8s.io/v1/ingresses"))
    except Exception as exc:
        logger.debug("Ingress listing failed: %s", exc)
        ingresses = []
    for ing in ingresses:
        meta = ing["metadata"]
        ns = meta.get("namespace", "")
        spec = ing.get("spec") or {}
        backends: set[str] = set()
        default = ((spec.get("defaultBackend") or {}).get("service") or {}).get("name")
        if default:
            backends.add(default)
        for rule in spec.get("rules", []) or []:
            for p in ((rule.get("http") or {}).get("paths") or []):
                name = ((p.get("backend") or {}).get("service") or {}).get("name")
                if name:
                    backends.add(name)
        relations = [ns_rel(ns)]
        relations += [
            rel(k8s_identifier(cluster_arn, ns, "Service", b), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
            for b in sorted(backends)
        ]
        hostnames = _lb_hostnames(ing)
        relations += [rel(h, EdgeType.ROUTE, "LOAD_BALANCED_BY", reverse=True) for h in hostnames]
        assets.append(
            asset(
                "Ingress",
                ns,
                meta["name"],
                AssetType.K8S_INGRESS,
                {
                    "ingress_class": spec.get("ingressClassName"),
                    "hosts": [r.get("host") for r in spec.get("rules", []) or [] if r.get("host")],
                    "backends": sorted(backends),
                    "load_balancer_hostnames": hostnames,
                    "tls": bool(spec.get("tls")),
                },
                relations,
                labels=meta.get("labels"),
                exposed=bool(hostnames),
            )
        )

    return assets


def collect_eks_workloads(
    session: Any,
    cluster: dict[str, Any],
    region: str,
    account_id: str | None,
    timeout: int = 10,
) -> list[CloudAsset]:
    """Map the Kubernetes objects of one EKS cluster (blocking; run in a thread)."""
    token = eks_token(session, cluster["name"], region)
    reader = KubernetesReader(
        cluster["endpoint"],
        (cluster.get("certificateAuthority") or {}).get("data"),
        token,
        timeout=timeout,
    )
    return map_cluster_objects(reader, cluster["arn"], region, account_id)


__all__ = [
    "KubernetesReader",
    "collect_eks_workloads",
    "eks_token",
    "map_cluster_objects",
]

