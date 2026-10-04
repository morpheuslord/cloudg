"""Identity extractors, IAM principals and policy bindings."""

from __future__ import annotations

from typing import Any, Iterable

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor, mark_exposed
from cloudg.inventory.gcp_relations.names import (
    _KSA_MEMBER_RE,
    _KSA_PRINCIPAL_RE,
    _POOL_RE,
    IMPERSONATION_ROLES,
    K8S_GKE_PREFIX,
    PRINCIPAL_PREFIX,
    PUBLIC_MEMBERS,
    _list,
    _num,
    dig,
    sa_email,
    sa_ref,
)
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType, NetworkEdge

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@_extractor("iam.googleapis.com/ServiceAccount")
def _service_account(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    email = sa_email(d.get("email"))
    pid = d.get("projectId") or ctx.project_id
    if email:
        out.alias(email, sa_ref(email), f"{PRINCIPAL_PREFIX}{sa_ref(email)}")
        for p in {pid, "-"} - {None}:
            out.alias(
                f"projects/{p}/serviceAccounts/{email}",
                f"//iam.googleapis.com/projects/{p}/serviceAccounts/{email}",
            )
        if d.get("uniqueId") and pid:
            out.alias(f"//iam.googleapis.com/projects/{pid}/serviceAccounts/{_num(d['uniqueId'])}")
    out.metadata.update(
        email=email,
        disabled=bool(d.get("disabled")),
        unique_id=_num(d.get("uniqueId")),
        principal_type="serviceAccount",
    )


@_extractor("iam.googleapis.com/ServiceAccountKey")
def _sa_key(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        ctx.name.split("/keys/", 1)[0], EdgeType.ATTACHED_TO, description="key of service account"
    )
    out.metadata.update(
        key_type=d.get("keyType"),
        key_origin=d.get("keyOrigin"),
        valid_after=d.get("validAfterTime"),
        valid_before=d.get("validBeforeTime"),
        disabled=bool(d.get("disabled")),
    )


@_extractor(
    "iam.googleapis.com/WorkloadIdentityPoolProvider", "iam.googleapis.com/WorkforcePoolProvider"
)
def _wif_provider(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(ctx.name.split("/providers/", 1)[0], EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        issuer_uri=dig(d, "oidc", "issuerUri"),
        allowed_audiences=list(dig(d, "oidc", "allowedAudiences", default=[]) or []),
        aws_account_id=dig(d, "aws", "accountId"),
        saml=bool(d.get("saml")),
        attribute_condition=d.get("attributeCondition"),
        attribute_mapping_keys=sorted((d.get("attributeMapping") or {}).keys()),
        disabled=bool(d.get("disabled")),
    )


@_extractor("iam.googleapis.com/Role")
def _custom_role(ctx: GCPContext, out: Extracted) -> None:
    perms = ctx.data.get("includedPermissions") or []
    out.metadata.update(permission_count=len(perms), stage=ctx.data.get("stage"))


@_extractor("apikeys.googleapis.com/Key")
def _api_key(ctx: GCPContext, out: Extracted) -> None:
    restrictions = ctx.data.get("restrictions") or {}
    out.metadata.update(
        restricted=bool(restrictions),
        api_targets=[
            t.get("service") for t in _list(restrictions.get("apiTargets")) if isinstance(t, dict)
        ],
    )


# ---------------------------------------------------------------------------
# IAM principals and bindings
# ---------------------------------------------------------------------------


def principal_kind(member: str) -> tuple[AssetType, str] | None:
    """(asset type, principal type) for an IAM member string, None to ignore."""
    if member in PUBLIC_MEMBERS or member.startswith("deleted:"):
        return None
    if _KSA_MEMBER_RE.match(member) or _KSA_PRINCIPAL_RE.match(member):
        return AssetType.K8S_SERVICE_ACCOUNT, "kubernetesServiceAccount"
    prefix = member.split(":", 1)[0]
    if member.startswith(("principal://", "principalSet://")):
        return AssetType.IDENTITY_PROVIDER, "principalSet" if member.startswith(
            "principalSet://"
        ) else "principal"
    return {
        "user": (AssetType.IDENTITY_USER, "user"),
        "group": (AssetType.IDENTITY_GROUP, "group"),
        "domain": (AssetType.IDENTITY_GROUP, "domain"),
        "serviceAccount": (AssetType.SERVICE_PRINCIPAL, "serviceAccount"),
        "projectOwner": (AssetType.IDENTITY_GROUP, "projectOwner"),
        "projectEditor": (AssetType.IDENTITY_GROUP, "projectEditor"),
        "projectViewer": (AssetType.IDENTITY_GROUP, "projectViewer"),
    }.get(prefix, (AssetType.IDENTITY_GROUP, prefix or "unknown"))


def ksa_identifier(member: str) -> str | None:
    """``k8s-gke://<pool project>/<ns>/<ksa>`` for a GKE workload identity member."""
    m = _KSA_MEMBER_RE.match(member) or _KSA_PRINCIPAL_RE.match(member)
    if not m:
        return None
    project, ns, ksa = m.groups()
    return f"{K8S_GKE_PREFIX}{project}/{ns}/{ksa}"


def principal_identifier(member: str) -> str:
    """The identifier relations and aliases use for a member."""
    ksa = ksa_identifier(member)
    if ksa:
        return ksa
    email = sa_email(member) if member.startswith("serviceAccount:") else None
    if email:
        return sa_ref(email)
    return f"{PRINCIPAL_PREFIX}{member}"


def _sa_home(email: str) -> tuple[str | None, bool]:
    """(home project, google-managed) of a service account email."""
    local, _, domain = email.partition("@")
    if domain.endswith(".iam.gserviceaccount.com"):
        project = domain[: -len(".iam.gserviceaccount.com")]
        if project.startswith("gcp-sa-") or local.startswith("service-"):
            return None, True
        return project, False
    if domain == "appspot.gserviceaccount.com":
        return local, False
    if domain == "developer.gserviceaccount.com":
        return None, False
    return None, True


def principal_asset(member: str, discovered_via: str = "iam_policy") -> CloudAsset | None:
    """Placeholder asset for an IAM principal that is not a collected resource.

    The asset is never ``external``: it is an identity, not an internet
    source. Its ``arn`` is ``gcp-principal:<member>`` (``k8s-gke://...`` for
    Kubernetes service accounts) and the member string is its name.
    """
    kind = principal_kind(member)
    if kind is None:
        return None
    asset_type, ptype = kind
    md: dict[str, Any] = {
        "member": member,
        "principal_type": ptype,
        "placeholder": True,
        "discovered_via": discovered_via,
    }
    aliases = [member, f"{PRINCIPAL_PREFIX}{member}"]
    arn = f"{PRINCIPAL_PREFIX}{member}"
    ksa = ksa_identifier(member)
    if ksa:
        arn = ksa
        md["workload_pool_project"] = ksa[len(K8S_GKE_PREFIX) :].split("/", 1)[0]
    elif ptype == "serviceAccount":
        email = sa_email(member)
        if email:
            home, managed = _sa_home(email)
            md.update(email=email, home_project=home, google_managed=managed)
            arn = f"{PRINCIPAL_PREFIX}{sa_ref(email)}"
            aliases = [email, sa_ref(email), arn]
    pool = _POOL_RE.match(member)
    rels = []
    if pool:
        md["identity_pool"] = f"//iam.googleapis.com/{pool.group(1)}"
        r = rel(
            md["identity_pool"],
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="federated identity pool",
        )
        if r:
            rels.append(r)
    if rels:
        md["relations"] = rels
    md["aliases"] = list(dict.fromkeys(aliases))
    return CloudAsset(
        arn=arn,
        name=member,
        asset_type=asset_type,
        provider=CloudProvider.GCP,
        region="global",
        account_id=None,
        metadata=md,
    )


def _index(assets: Iterable[CloudAsset]) -> dict[str, CloudAsset]:
    idx: dict[str, CloudAsset] = {}
    for a in assets:
        for ident in [a.arn, *(a.metadata.get("aliases") or [])]:
            if isinstance(ident, str) and ident:
                idx.setdefault(ident, a)
                idx.setdefault(ident.lower(), a)
    return idx


def _index_placeholder(idx: dict[str, CloudAsset], asset: CloudAsset) -> None:
    """Make a freshly created placeholder resolvable by its arn and aliases."""
    for ident in [asset.arn, *asset.metadata.get("aliases", [])]:
        idx.setdefault(ident, asset)
        idx.setdefault(ident.lower(), asset)


def _append_relation(asset: CloudAsset, relation: dict[str, Any] | None) -> None:
    if not relation:
        return
    rels = asset.metadata.setdefault("relations", [])
    if relation not in rels:
        rels.append(relation)


def _mark_public(target: CloudAsset, member: str, role: str) -> None:
    """``allUsers`` / ``allAuthenticatedUsers`` binding: the resource is public."""
    mark_exposed(target, f"IAM {role} granted to {member}")
    public = target.metadata.setdefault("public_access", [])
    if {"member": member, "role": role} not in public:
        public.append({"member": member, "role": role})


def _is_sa_resource(resource: str) -> bool:
    return (
        "/serviceAccounts/" in resource
        and resource.startswith("//iam.googleapis.com/")
        and "/keys/" not in resource
    )


class _PolicyBinder:
    """State of one :func:`apply_iam_policies` run: the identifier index, the
    placeholders created so far and the grants folded per (principal, resource, edge)."""

    def __init__(self, assets: list[CloudAsset]) -> None:
        self.idx = _index(assets)
        self.created: list[CloudAsset] = []
        self.grants: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.principals: dict[str, CloudAsset] = {}

    def principal_for(self, member: str) -> CloudAsset | None:
        ident = principal_identifier(member)
        found = self.idx.get(ident) or self.idx.get(ident.lower())
        if found is None and ident.startswith("serviceAccount:"):
            found = self.idx.get(f"{PRINCIPAL_PREFIX}{ident}")
        if found is not None:
            return found
        asset = principal_asset(member)
        if asset is None:
            return None
        self.created.append(asset)
        _index_placeholder(self.idx, asset)
        return asset

    def bind_policy(self, pol: dict[str, Any]) -> None:
        resource = pol.get("resource")
        if not isinstance(resource, str) or not resource:
            return
        target = self.idx.get(resource)
        sa_resource = _is_sa_resource(resource)
        for binding in (pol.get("policy") or {}).get("bindings") or []:
            role = binding.get("role") or ""
            cond = (binding.get("condition") or {}).get("title")
            for member in binding.get("members") or []:
                if not isinstance(member, str):
                    continue
                if member in PUBLIC_MEMBERS:
                    if target is not None:
                        _mark_public(target, member, role)
                    continue
                edge = (
                    EdgeType.ASSUMES_ROLE
                    if sa_resource and role in IMPERSONATION_ROLES
                    else EdgeType.GRANTS_ACCESS
                )
                self.grant(member, target, (resource, edge), role, cond)

    def grant(
        self,
        member: str,
        target: CloudAsset | None,
        key: tuple[str, EdgeType],
        role: str,
        cond: str | None,
    ) -> None:
        principal = self.principal_for(member)
        if principal is None or principal is target:
            return
        self.principals[principal.id] = principal
        resource, edge = key
        info = self.grants.setdefault(
            (principal.id, resource, edge.value), {"roles": [], "conditions": []}
        )
        if role not in info["roles"]:
            info["roles"].append(role)
        if cond and cond not in info["conditions"]:
            info["conditions"].append(cond)

    def emit(self) -> None:
        """One relation per (principal, resource, edge) carrying every role."""
        for (pid, resource, edge_value), info in self.grants.items():
            principal = self.principals[pid]
            edge = EdgeType(edge_value)
            assumes = edge == EdgeType.ASSUMES_ROLE
            desc = (
                f"{principal.name} can act as this service account"
                if assumes
                else f"{principal.name} has {', '.join(info['roles'])}"
            )
            _append_relation(
                principal,
                rel(
                    resource,
                    edge,
                    "ROLE_ASSUMES_ROLE" if assumes else "POLICY_ALLOWS_ACTION",
                    description=desc,
                    role=info["roles"][0],
                    roles=info["roles"],
                    condition=", ".join(info["conditions"]) or None,
                ),
            )


def apply_iam_policies(
    assets: list[CloudAsset], policies: Iterable[dict[str, Any]]
) -> list[CloudAsset]:
    """Turn IAM policy search results into typed relations.

    Each binding member becomes the source of a relation on its principal
    asset: the collected service account (resolved by email), an existing
    principal, or a new non-external placeholder. ``allUsers`` and
    ``allAuthenticatedUsers`` only mark the bound resource internet-exposed.

    Relations (principal -> resource):
      - GRANTS_ACCESS / POLICY_ALLOWS_ACTION with ``role``, ``roles`` and
        ``condition`` properties;
      - ASSUMES_ROLE / ROLE_ASSUMES_ROLE for impersonation roles granted on
        a service account (token creator, SA user, workload identity user).

    Args:
        assets: Collected assets (principals found here are reused).
        policies: Plain dicts ``{"resource": ..., "policy": {"bindings": [...]}}``.

    Returns:
        Newly created principal placeholder assets.
    """
    binder = _PolicyBinder(assets)
    for pol in policies:
        binder.bind_policy(pol)
    binder.emit()
    return binder.created


def ensure_service_account_principals(assets: list[CloudAsset]) -> list[CloudAsset]:
    """Placeholders for service accounts referenced (``serviceAccount:<email>``)
    by workloads but not collected, e.g. Google-managed service agents."""
    idx = _index(assets)
    created: list[CloudAsset] = []
    for a in list(assets):
        for r in a.metadata.get("relations") or []:
            target = r.get("target") if isinstance(r, dict) else None
            if not isinstance(target, str) or not target.startswith("serviceAccount:"):
                continue
            if target in idx or target.lower() in idx:
                continue
            placeholder = principal_asset(target, discovered_via="workload_reference")
            if placeholder is None:
                continue
            created.append(placeholder)
            _index_placeholder(idx, placeholder)
    return created


def merge_gcp_principals(
    assets: list[CloudAsset], edges: list[NetworkEdge] | None = None
) -> tuple[list[CloudAsset], list[NetworkEdge]]:
    """Fold principal placeholders into the real assets they stand for.

    Per-project collection creates a placeholder for a service account (or
    Kubernetes service account) that lives in another project. Once every
    project is collected, call this to move the placeholder's relations and
    exposure onto the real asset and drop the placeholder, so identities are
    not duplicated or left ambiguous for the linker. Edges pointing at a
    dropped placeholder are re-pointed.

    Args:
        assets: All collected assets (any provider; only GCP ones are touched).
        edges: Already-collected edges to re-point (optional).

    Returns:
        (assets, edges) with placeholders merged.
    """
    edges = list(edges or [])
    real: dict[str, CloudAsset] = {}
    for a in assets:
        if a.provider != CloudProvider.GCP or a.metadata.get("placeholder"):
            continue
        for ident in a.metadata.get("aliases") or []:
            if isinstance(ident, str) and (ident.startswith(("serviceAccount:", K8S_GKE_PREFIX))):
                real.setdefault(ident.lower(), a)
    remap: dict[str, str] = {}
    out: list[CloudAsset] = []
    for a in assets:
        if a.provider == CloudProvider.GCP and a.metadata.get("placeholder"):
            target = None
            for ident in [a.arn, *(a.metadata.get("aliases") or [])]:
                if isinstance(ident, str):
                    target = real.get(ident.lower())
                    if target is not None:
                        break
            if target is not None and target.id != a.id:
                for r in a.metadata.get("relations") or []:
                    _append_relation(target, r)
                if a.is_internet_exposed:
                    target.is_internet_exposed = True
                remap[a.id] = target.id
                continue
        out.append(a)
    if remap:
        new_edges = []
        for e in edges:
            s, t = remap.get(e.source_id, e.source_id), remap.get(e.target_id, e.target_id)
            if s == t:
                continue
            if s != e.source_id or t != e.target_id:
                e = e.model_copy(update={"source_id": s, "target_id": t})
            new_edges.append(e)
        edges = new_edges
    return out, edges
