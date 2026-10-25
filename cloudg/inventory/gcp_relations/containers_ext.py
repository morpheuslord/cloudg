"""Containers beyond GKE: Artifact Registry images and upstreams, Binary
Authorization, GKE fleets (Hub) and Backup for GKE."""

from __future__ import annotations

import re

from cloudg.inventory.gcp_relations._refs import crm_ref, parent_of, secret_version_ref
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, _num, dig, full_name
from cloudg.schema.models import EdgeType

_CLUSTER_KEY_RE = re.compile(r"^([a-z0-9-]+)\.(.+)$")


# ---------------------------------------------------------------------------
# Artifact Registry
# ---------------------------------------------------------------------------


@_extractor("artifactregistry.googleapis.com/DockerImage")
def _docker_image(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "dockerImages"), EdgeType.CONTAINS, reverse=True)
    uri = d.get("uri")
    if isinstance(uri, str) and uri:
        out.alias(uri, f"https://{uri}")
    out.metadata.update(
        uri=uri,
        tags=list(d.get("tags") or []),
        image_size_bytes=_num(d.get("imageSizeBytes")),
        upload_time=d.get("uploadTime"),
        build_time=d.get("buildTime"),
        media_type=d.get("mediaType"),
    )


@_extractor("artifactregistry.googleapis.com/Repository")
def _ar_repo_upstreams(ctx: GCPContext, out: Extracted) -> None:
    """Virtual repository upstreams, remote upstream credentials and scanning."""
    d = ctx.data
    virtual = d.get("virtualRepositoryConfig") or {}
    for policy in _list(virtual.get("upstreamPolicies")):
        if isinstance(policy, dict):
            out.add(
                full_name(policy.get("repository"), "artifactregistry"),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="virtual repository upstream",
                priority=policy.get("priority"),
            )
    remote = d.get("remoteRepositoryConfig") or {}
    out.add(
        secret_version_ref(
            dig(
                remote,
                "upstreamCredentials",
                "usernamePasswordCredentials",
                "passwordSecretVersion",
            )
        ),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="remote upstream credentials",
    )
    upstream = None
    for key, cfg in remote.items():
        if key.endswith("Repository") and isinstance(cfg, dict):
            upstream = (
                cfg.get("publicRepository")
                or dig(cfg, "customRepository", "uri")
                or dig(cfg, "commonRepository", "uri")
            )
    scan = d.get("vulnerabilityScanningConfig") or {}
    out.metadata.update(
        upstream=upstream,
        remote_description=remote.get("description"),
        vulnerability_scanning=scan.get("enablementState") or scan.get("enablementConfig"),
        cleanup_policy_count=len(d.get("cleanupPolicies") or {}),
    )


# ---------------------------------------------------------------------------
# Binary Authorization
# ---------------------------------------------------------------------------


def _admission_rule(rule: object) -> dict:
    if not isinstance(rule, dict):
        return {}
    return {
        "evaluation_mode": rule.get("evaluationMode"),
        "enforcement_mode": rule.get("enforcementMode"),
        "attestors": list(rule.get("requireAttestationsBy") or []),
    }


@_extractor("binaryauthorization.googleapis.com/Policy")
def _binauthz_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid = ctx.project_id
    attestors: list[str] = []
    for key, rule in (d.get("clusterAdmissionRules") or {}).items():
        m = _CLUSTER_KEY_RE.match(str(key))
        if m and pid:
            loc, cluster = m.groups()
            out.add(
                f"//container.googleapis.com/projects/{pid}/locations/{loc}/clusters/{cluster}",
                EdgeType.GOVERNS,
                "COMPLIANCE_GOVERNS",
                description="cluster admission rule",
                **_admission_rule(rule),
            )
        attestors += _admission_rule(rule).get("attestors", [])
    default = _admission_rule(d.get("defaultAdmissionRule"))
    attestors += default.get("attestors", [])
    out.add(
        crm_ref(f"projects/{pid}") if pid else None,
        EdgeType.GOVERNS,
        "COMPLIANCE_GOVERNS",
        description="default admission rule for every cluster in the project",
        **default,
    )
    for att in dict.fromkeys(attestors):
        out.add(full_name(att, "binaryauthorization"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        default_rule=default,
        global_policy_evaluation_mode=d.get("globalPolicyEvaluationMode"),
        allowlist_pattern_count=len(_list(d.get("admissionWhitelistPatterns"))),
    )


@_extractor("binaryauthorization.googleapis.com/Attestor")
def _binauthz_attestor(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    note = d.get("userOwnedGrafeasNote") or {}
    out.sa(note.get("delegationServiceAccountEmail"), ctx, "attestor verification identity")
    out.metadata.update(
        note=note.get("noteReference"), public_key_count=len(_list(note.get("publicKeys")))
    )


@_extractor("binaryauthorization.googleapis.com/PlatformPolicy")
def _binauthz_platform_policy(ctx: GCPContext, out: Extracted) -> None:
    gke = ctx.data.get("gkePolicy") or {}
    out.metadata["check_set_count"] = len(_list(gke.get("checkSets")))


# ---------------------------------------------------------------------------
# GKE fleets (gkehub)
# ---------------------------------------------------------------------------


@_extractor("gkehub.googleapis.com/Membership")
def _fleet_membership(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    endpoint = d.get("endpoint") or {}
    for key in (
        "gkeCluster",
        "onPremCluster",
        "multiCloudCluster",
        "edgeCluster",
        "applianceCluster",
    ):
        out.add(
            full_name(dig(endpoint, key, "resourceLink")),
            EdgeType.MANAGES,
            "OWNED_BY",
            description="fleet member cluster",
        )
    authority = d.get("authority") or {}
    out.metadata.update(
        workload_identity_pool=authority.get("workloadIdentityPool"),
        issuer=authority.get("issuer"),
        unique_id=d.get("uniqueId"),
    )


@_extractor("gkehub.googleapis.com/Feature")
def _fleet_feature(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for membership in (d.get("membershipSpecs") or {}).keys():
        out.add(
            full_name(membership, "gkehub"),
            EdgeType.MANAGES,
            "OWNED_BY",
            description=f"fleet feature {ctx.name.rsplit('/', 1)[-1]}",
        )
    out.metadata["feature_state"] = dig(d, "resourceState", "state")


@_extractor("gkehub.googleapis.com/MembershipBinding")
def _fleet_binding(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "bindings"), EdgeType.CONTAINS, reverse=True)
    out.add(full_name(ctx.data.get("scope"), "gkehub"), EdgeType.REFERENCES, "DEPENDS_ON")


@_extractor("gkehub.googleapis.com/Namespace", "gkehub.googleapis.com/RBACRoleBinding")
def _fleet_scoped(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    scope = parent_of(ctx.name, "namespaces") or parent_of(ctx.name, "rbacrolebindings")
    if scope and "/namespaces/" in scope:
        scope = parent_of(scope, "namespaces")
    out.add(scope, EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        user=d.get("user"),
        group=d.get("group"),
        role=dig(d, "role", "predefinedRole") or dig(d, "role", "customRole"),
    )


# ---------------------------------------------------------------------------
# Backup for GKE
# ---------------------------------------------------------------------------


@_extractor("gkebackup.googleapis.com/BackupPlan")
def _gke_backup_plan(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("cluster"), "container"),
        EdgeType.MANAGES,
        "BACKUP_TO",
        description="Backup for GKE plan",
    )
    cfg = d.get("backupConfig") or {}
    out.metadata.update(
        cron_schedule=dig(d, "backupSchedule", "cronSchedule"),
        retention_days=_num(dig(d, "retentionPolicy", "backupRetainDays")),
        all_namespaces=cfg.get("allNamespaces"),
        include_secrets=cfg.get("includeSecrets"),
        include_volume_data=cfg.get("includeVolumeData"),
        deactivated=d.get("deactivated"),
    )


@_extractor("gkebackup.googleapis.com/Backup")
def _gke_backup(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "backups"), EdgeType.CONTAINS, reverse=True)
    out.metadata["backup_state"] = ctx.data.get("state")


@_extractor("gkebackup.googleapis.com/RestorePlan")
def _gke_restore_plan(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("cluster"), "container"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("backupPlan"), "gkebackup"), EdgeType.REFERENCES, "DEPENDS_ON")


# ---------------------------------------------------------------------------
# Kubernetes namespaces and RBAC roles (Cloud Asset Inventory GKE objects)
# ---------------------------------------------------------------------------


@_extractor("k8s.io/Namespace")
def _k8s_namespace(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        parent_of(ctx.name, "k8s"),
        EdgeType.CONTAINS,
        "CLUSTER_CONTAINS_SERVICE",
        reverse=True,
        description="cluster namespace",
    )
    out.metadata["phase"] = dig(ctx.data, "status", "phase")


@_extractor("rbac.authorization.k8s.io/ClusterRole", "rbac.authorization.k8s.io/Role")
def _k8s_role(ctx: GCPContext, out: Extracted) -> None:
    rules = [r for r in _list(ctx.data.get("rules")) if isinstance(r, dict)]
    out.add(parent_of(ctx.name, "k8s"), EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        rule_count=len(rules),
        wildcard=any(
            "*" in (r.get("verbs") or []) or "*" in (r.get("resources") or []) for r in rules
        ),
        reads_secrets=any(
            "secrets" in (r.get("resources") or [])
            and bool(set(r.get("verbs") or []) & {"get", "list", "watch", "*"})
            for r in rules
        ),
    )


@_extractor("gkehub.googleapis.com/Fleet", "gkehub.googleapis.com/Scope")
def _fleet(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        display_name=d.get("displayName"),
        default_cluster_config=sorted((d.get("defaultClusterConfig") or {}).keys()) or None,
        namespace_labels=d.get("namespaceLabels"),
    )
