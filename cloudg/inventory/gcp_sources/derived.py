"""Cross-asset passes of the deep GCP collector (no API calls).

Some GCP relations only exist between two other assets, or need the whole
inventory to resolve. These passes run once every asset is built:

- tag bindings become ``TAGGED_WITH`` relations on the bound resource;
- resource policies on instances get the right verb by their kind
  (snapshot schedule ``BACKUP_TO``, instance schedule ``SCHEDULED_BY``);
- a rotating secret ``ROTATES_SECRET`` the functions / services that
  consume its rotation topic;
- ``goog-dm`` and ``managed-by-cnrm`` labels link Deployment Manager and
  Config Connector (``MANAGES`` / ``OWNED_BY``);
- Principal Access Boundary bindings link the principal set to the policy;
- OS Config label / zone filters are matched to instances;
- API Gateway JWT providers become ``AUTHORIZER`` assets;
- ``gcp-principal:`` relation targets that are not assets get placeholders.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.gcp_relations.apis import jwt_issuer_target
from cloudg.inventory.gcp_relations.iam import principal_asset
from cloudg.inventory.gcp_relations.names import PRINCIPAL_PREFIX, api_service
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

_INSTANCE = "compute.googleapis.com/Instance"


def _index(assets: list[CloudAsset]) -> dict[str, CloudAsset]:
    idx: dict[str, CloudAsset] = {}
    for a in assets:
        for ident in [a.arn, *(a.metadata.get("aliases") or [])]:
            if isinstance(ident, str) and ident:
                idx.setdefault(ident, a)
                idx.setdefault(ident.lower(), a)
    return idx


def _append(asset: CloudAsset, relation: dict[str, Any] | None) -> None:
    if relation:
        rels = asset.metadata.setdefault("relations", [])
        if relation not in rels:
            rels.append(relation)


def _gtype(a: CloudAsset) -> Any:
    return a.metadata.get("gcp_asset_type")


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


def fold_tag_bindings(assets: list[CloudAsset]) -> list[CloudAsset]:
    """Replace each tag binding by a TAGGED_WITH relation on the resource it binds."""
    idx = _index(assets)
    out: list[CloudAsset] = []
    for a in assets:
        if _gtype(a) != "cloudresourcemanager.googleapis.com/TagBinding":
            out.append(a)
            continue
        resource = idx.get(a.metadata.get("bound_resource") or "")
        value = a.metadata.get("tag_value")
        relation = rel(
            value,
            EdgeType.REFERENCES,
            "TAGGED_WITH",
            description=a.metadata.get("tag_value_namespaced_name"),
        )
        if resource is None:
            _append(a, relation)
            out.append(a)
            continue
        _append(resource, relation)
        tags = resource.metadata.setdefault("resource_manager_tags", [])
        name = a.metadata.get("tag_value_namespaced_name") or value
        if name and name not in tags:
            tags.append(name)
    return out


# ---------------------------------------------------------------------------
# Instance resource policies
# ---------------------------------------------------------------------------

_POLICY_VERBS = {
    "instance_schedule": (EdgeType.MANAGES, "SCHEDULED_BY", True, "instance start / stop schedule"),
    "snapshot_schedule": (EdgeType.MANAGES, "BACKUP_TO", True, "snapshot schedule"),
}


def link_instance_policies(assets: list[CloudAsset]) -> None:
    """Instance resource policies: schedules manage the VM, placement is a dependency."""
    idx = _index(assets)
    for vm in assets:
        if _gtype(vm) != _INSTANCE:
            continue
        for ref in vm.metadata.get("resource_policies") or []:
            policy = idx.get(ref)
            kind = policy.metadata.get("policy_kind") if policy is not None else None
            edge, verb, reverse, desc = _POLICY_VERBS.get(
                kind, (EdgeType.REFERENCES, "DEPENDS_ON", False, f"{kind or 'resource'} policy")
            )
            _append(vm, rel(ref, edge, verb, reverse=reverse, description=desc))


# ---------------------------------------------------------------------------
# Secret rotation
# ---------------------------------------------------------------------------


def _topic_consumers(assets: list[CloudAsset]) -> dict[str, list[str]]:
    """Pub/Sub topic -> identifiers of what its messages invoke."""
    consumers: dict[str, list[str]] = {}

    def add(topic: str, target: str) -> None:
        if target not in consumers.setdefault(topic, []):
            consumers[topic].append(target)

    for a in assets:
        rels = [r for r in a.metadata.get("relations") or [] if isinstance(r, dict)]
        topics = [
            r["target"]
            for r in rels
            if r.get("reverse")
            and api_service(r.get("target")) == "pubsub"
            and "/topics/" in str(r.get("target"))
            and r.get("edge") in (EdgeType.INVOKES.value,)
        ]
        if not topics or not a.arn:
            continue
        gtype = _gtype(a) or ""
        if gtype.startswith(("cloudfunctions.", "run.")):
            for t in topics:
                add(t, a.arn)
            continue
        # Subscriptions and Eventarc triggers forward to what they invoke
        forwards = [
            r["target"]
            for r in rels
            if not r.get("reverse") and r.get("edge") == EdgeType.INVOKES.value and r.get("target")
        ]
        for t in topics:
            for f in forwards:
                if api_service(f) != "pubsub":
                    add(t, f)
    return consumers


def link_secret_rotation(assets: list[CloudAsset]) -> None:
    """A rotating secret ROTATES_SECRET the handlers of its rotation topics (AWS: the rotation Lambda)."""
    consumers: dict[str, list[str]] | None = None
    for secret in assets:
        if _gtype(secret) != "secretmanager.googleapis.com/Secret":
            continue
        topics = secret.metadata.get("rotation_topics") or []
        if not topics or not secret.metadata.get("rotation_period"):
            continue
        if consumers is None:
            consumers = _topic_consumers(assets)
        for topic in topics:
            for handler in consumers.get(topic, []):
                _append(
                    secret,
                    rel(
                        handler,
                        EdgeType.INVOKES,
                        "ROTATES_SECRET",
                        description="rotation handler (subscribes to the rotation topic)",
                        topic=topic,
                    ),
                )


# ---------------------------------------------------------------------------
# Deployment Manager / Config Connector labels
# ---------------------------------------------------------------------------


def _kcc_clusters(assets: list[CloudAsset]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for a in assets:
        if _gtype(a) != "container.googleapis.com/Cluster" or not a.account_id:
            continue
        data = (a.raw_data or {}).get("data") or {}
        addons = data.get("addonsConfig") or {}
        if (addons.get("configConnectorConfig") or {}).get("enabled"):
            out.setdefault(a.account_id, []).append(a.arn)
    return out


def link_managed_labels(assets: list[CloudAsset]) -> None:
    """``goog-dm`` -> Deployment Manager deployment; ``managed-by-cnrm`` -> Config Connector."""
    kcc = _kcc_clusters(assets)
    for a in assets:
        if a.provider != CloudProvider.GCP or not a.tags:
            continue
        project = a.account_id
        dm = a.tags.get("goog-dm")
        if dm and project:
            a.metadata["managed_by"] = "deployment-manager"
            _append(
                a,
                rel(
                    f"//deploymentmanager.googleapis.com/projects/{project}/global/deployments/{dm}",
                    EdgeType.MANAGES,
                    "OWNED_BY",
                    reverse=True,
                    description="created by Deployment Manager",
                ),
            )
        if str(a.tags.get("managed-by-cnrm", "")).lower() == "true":
            a.metadata["managed_by"] = "config-connector"
            clusters = kcc.get(project or "", [])
            if len(clusters) == 1:
                _append(
                    a,
                    rel(
                        clusters[0],
                        EdgeType.MANAGES,
                        "OWNED_BY",
                        reverse=True,
                        description="managed by Config Connector",
                    ),
                )
        if str(a.tags.get("goog-terraform-provisioned", "")).lower() == "true":
            a.metadata.setdefault("managed_by", "terraform")


# ---------------------------------------------------------------------------
# Principal Access Boundary bindings
# ---------------------------------------------------------------------------


def fold_policy_bindings(assets: list[CloudAsset]) -> None:
    """Principal set -> PERMISSION_BOUNDARY_LIMITS -> Principal Access Boundary policy."""
    idx = _index(assets)
    for binding in assets:
        if _gtype(binding) != "iam.googleapis.com/PolicyBinding":
            continue
        policy = idx.get(binding.metadata.get("policy") or "")
        target = binding.metadata.get("target_principal_set")
        if policy is not None and target:
            _append(
                policy,
                rel(
                    target,
                    EdgeType.REFERENCES,
                    "PERMISSION_BOUNDARY_LIMITS",
                    reverse=True,
                    description="principals in this set are limited by the boundary",
                    binding=binding.arn,
                ),
            )


# ---------------------------------------------------------------------------
# OS Config instance filters
# ---------------------------------------------------------------------------


def _matches(vm: CloudAsset, flt: dict[str, Any]) -> bool:
    if flt.get("zones") and vm.region not in flt["zones"]:
        return False
    if flt.get("name_prefixes") and not any(vm.name.startswith(p) for p in flt["name_prefixes"]):
        return False
    labels = vm.tags or {}
    groups = flt.get("labels") or []
    if groups and not any(all(labels.get(k) == v for k, v in g.items()) for g in groups):
        return False
    for g in flt.get("exclusion_labels") or []:
        if g and all(labels.get(k) == v for k, v in g.items()):
            return False
    return bool(flt.get("zones") or flt.get("name_prefixes") or groups)


def link_os_config_filters(assets: list[CloudAsset]) -> None:
    """Patch deployments and OS policy assignments MANAGES / SCHEDULED_BY matching VMs."""
    vms = [a for a in assets if _gtype(a) == _INSTANCE]
    for cfg in assets:
        if _gtype(cfg) not in (
            "osconfig.googleapis.com/PatchDeployment",
            "osconfig.googleapis.com/OSPolicyAssignment",
        ):
            continue
        flt = cfg.metadata.get("instance_filter") or {}
        if not flt or flt.get("all"):
            continue
        for vm in vms:
            if vm.account_id == cfg.account_id and _matches(vm, flt):
                _append(
                    cfg,
                    rel(
                        vm.arn,
                        EdgeType.MANAGES,
                        "SCHEDULED_BY",
                        description="instance filter match",
                    ),
                )


# ---------------------------------------------------------------------------
# API Gateway authorizers
# ---------------------------------------------------------------------------


def authorizer_assets(assets: list[CloudAsset]) -> list[CloudAsset]:
    """An AUTHORIZER per JWT provider declared in an API Gateway config."""
    out: list[CloudAsset] = []
    for cfg in assets:
        for p in cfg.metadata.get("jwt_providers") or []:
            if not isinstance(p, dict) or not p.get("name"):
                continue
            relations = [
                rel(cfg.arn, EdgeType.CONTAINS, reverse=True, description="API config authorizer"),
                rel(
                    jwt_issuer_target(p.get("issuer")),
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="token issuer",
                ),
            ]
            out.append(
                CloudAsset(
                    arn=f"{cfg.arn}/authorizers/{p['name']}",
                    name=p["name"],
                    asset_type=AssetType.AUTHORIZER,
                    provider=CloudProvider.GCP,
                    region=cfg.region,
                    account_id=cfg.account_id,
                    metadata={
                        "gcp_asset_type": "apigateway.googleapis.com/Authorizer",
                        "project_id": cfg.account_id,
                        "authorizer_type": "JWT",
                        "issuer": p.get("issuer"),
                        "jwks_uri": p.get("jwks_uri"),
                        "audiences": p.get("audiences") or [],
                        "relations": [r for r in relations if r],
                        "discovered_via": "api config document",
                    },
                )
            )
    return out


# ---------------------------------------------------------------------------
# Principal placeholders
# ---------------------------------------------------------------------------


def ensure_principal_placeholders(assets: list[CloudAsset]) -> list[CloudAsset]:
    """Placeholders for ``gcp-principal:<member>`` targets (deny rules, PAM, groups ...)."""
    idx = _index(assets)
    created: list[CloudAsset] = []
    for a in list(assets):
        for r in a.metadata.get("relations") or []:
            target = r.get("target") if isinstance(r, dict) else None
            if not isinstance(target, str) or not target.startswith(PRINCIPAL_PREFIX):
                continue
            if target in idx or target.lower() in idx:
                continue
            placeholder = principal_asset(
                target[len(PRINCIPAL_PREFIX) :], discovered_via="relation_reference"
            )
            if placeholder is None:
                continue
            created.append(placeholder)
            for ident in [placeholder.arn, *placeholder.metadata.get("aliases", [])]:
                idx.setdefault(ident, placeholder)
                idx.setdefault(ident.lower(), placeholder)
    return created


def cap_images(
    records: list[dict[str, Any]], max_per_repository: int | None
) -> list[dict[str, Any]]:
    """Keep the newest ``max_per_repository`` Docker images per repository."""
    if not max_per_repository or max_per_repository <= 0:
        return records
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        if rec.get("asset_type") == "artifactregistry.googleapis.com/DockerImage":
            repo = str(rec.get("name", "")).split("/dockerImages/", 1)[0]
            by_repo.setdefault(repo, []).append(rec)
    drop: set[int] = set()
    for images in by_repo.values():
        if len(images) <= max_per_repository:
            continue
        images.sort(key=lambda r: str((r.get("data") or {}).get("uploadTime") or ""), reverse=True)
        drop.update(id(r) for r in images[max_per_repository:])
    return [r for r in records if id(r) not in drop]


PASSES: tuple[tuple[str, Callable[[list[CloudAsset]], Any]], ...] = (
    ("instance_policies", link_instance_policies),
    ("secret_rotation", link_secret_rotation),
    ("managed_labels", link_managed_labels),
    ("policy_bindings", fold_policy_bindings),
    ("os_config_filters", link_os_config_filters),
)


__all__ = [
    "PASSES",
    "authorizer_assets",
    "cap_images",
    "ensure_principal_placeholders",
    "fold_policy_bindings",
    "fold_tag_bindings",
    "link_instance_policies",
    "link_managed_labels",
    "link_os_config_filters",
    "link_secret_rotation",
]
