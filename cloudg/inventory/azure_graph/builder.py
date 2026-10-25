"""AzureAssetBuilder: ARM-shaped rows -> linked CloudAssets."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Iterable

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.azure_graph.arm_types import asset_type_from_arm
from cloudg.inventory.azure_graph.helpers import (
    _GUID_TAIL_RE,
    ACR_PULL_ROLE_ID,
    BUILTIN_ROLES,
    PRIVILEGED_ROLES,
    _get,
    _lower,
    _tags,
    normalize_scope,
    principal_ref,
    resource_group_name,
    sanitize,
    subscription_of,
    subscription_ref,
)
from cloudg.inventory.azure_graph.query import (
    containers_query,
    defender_query,
    resources_query,
    role_assignments_query,
    run_query,
)
from cloudg.inventory.azure_graph.registry import _COMMON, _EXTRACTORS, _ROW_HANDLERS, _Draft
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger("cloudg.inventory.azure_graph")


def _role_relation(
    ra: dict[str, Any], props: dict[str, Any], scope: str | None, ptype: Any
) -> tuple[str, dict[str, Any] | None]:
    """Role GUID and the GRANTS_ACCESS relation of one role assignment row."""
    rd = ra.get("roleDefinitionId") or _get(props, "roleDefinitionId") or ""
    m = _GUID_TAIL_RE.search(str(rd))
    guid = (ra.get("roleGuid") or (m.group(1) if m else "")).lower()
    role_name = ra.get("roleName") or BUILTIN_ROLES.get(guid) or guid or "unknown role"
    rl = role_name.lower()
    privileged = rl in PRIVILEGED_ROLES or rl.endswith("administrator") or rl.endswith("data owner")
    eligible = bool(ra.get("_eligible"))
    relation = rel(
        scope,
        EdgeType.GRANTS_ACCESS,
        "POLICY_ALLOWS_ACTION",
        description=f"{role_name} on {scope}" + (" (PIM eligible)" if eligible else ""),
        role=role_name,
        role_definition_id=rd,
        privileged=privileged,
        principal_type=ptype,
        assignment_id=ra.get("id"),
        condition=_get(props, "condition"),
        eligible=eligible or None,
        inherited_from=ra.get("_inherited_from"),
    )
    return guid, relation


def _pricing_resource(pricing_id: Any) -> str | None:
    """The resource a resource-level Defender pricing belongs to (None at subscription level)."""
    rid = str(pricing_id or "")
    cut = rid.lower().find("/providers/microsoft.security/pricings/")
    if cut <= 0:
        return None
    owner = rid[:cut]
    return owner if "/providers/" in owner.lower() else None


def _unique_relations(relations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop repeated (target, edge, direction, relationship) relations, keeping order."""
    rels: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for r in relations:
        k = (
            str(r.get("target")).lower(),
            r.get("edge"),
            r.get("reverse", False),
            r.get("relationship"),
        )
        if k not in seen:
            seen.add(k)
            rels.append(r)
    return rels


def _draft_asset(d: _Draft) -> CloudAsset:
    md = dict(d.md)
    md["properties"] = sanitize(d.props)
    rels = _unique_relations(d.relations)
    if rels:
        md["relations"] = rels
    if d.aliases:
        md["aliases"] = list(dict.fromkeys(d.aliases))
    return CloudAsset(
        arn=d.id,
        name=d.name,
        asset_type=d.asset_type,
        provider=CloudProvider.AZURE,
        region=d.region,
        account_id=d.account_id,
        tags=d.tags,
        metadata=md,
        raw_data={"id": d.id, "type": d.row.get("type")},
        is_internet_exposed=d.exposed,
    )


class AzureAssetBuilder:
    """Turn ARM-shaped rows into linked CloudAssets for one subscription.

    Args:
        subscription_id: Subscription the rows belong to.
        discovered_via: Collection source recorded in ``metadata["collected_via"]``.
    """

    def __init__(self, subscription_id: str, discovered_via: str = "resource-graph") -> None:
        self.subscription_id = subscription_id
        self.discovered_via = discovered_via
        self._drafts: dict[str, _Draft] = {}
        self._deferred: list[tuple[str, dict[str, Any]]] = []
        self._principal_owner: dict[str, str] = {}
        self._principal_types: dict[str, str | None] = {}
        self._kubelets: dict[str, list[str]] = {}
        self._role_rows: list[dict[str, Any]] = []
        self._extra: list[CloudAsset] = []
        self._subscription_row: dict[str, Any] | None = None
        self._with_subscription = False
        self._finalizers: list[Callable[["AzureAssetBuilder"], None]] = []
        self._role_definitions: dict[str, dict[str, Any]] = {}
        self._pricing_overrides: dict[str, bool] = {}
        self._pricings_seen = False
        self.state: dict[str, Any] = {}  # scratch space shared by extractors and handlers

    # ── registration hooks used by extractors ──

    def register_principal(self, principal_id: str, draft: _Draft) -> None:
        self._principal_owner.setdefault(principal_id.lower(), draft.id.lower())

    def note_principal(self, principal_id: Any, principal_type: str | None) -> None:
        if isinstance(principal_id, str) and principal_id:
            key = principal_id.lower()
            if principal_type or key not in self._principal_types:
                self._principal_types[key] = principal_type

    def register_kubelet(self, object_id: str, draft: _Draft) -> None:
        self._kubelets.setdefault(object_id.lower(), []).append(draft.id)

    def defer(self, owner_id: str | None, relation: dict[str, Any] | None) -> None:
        """Attach a relation to another (possibly not yet built) asset."""
        if owner_id and relation:
            self._deferred.append((owner_id.lower(), relation))

    def at_build(self, fn: Callable[["AzureAssetBuilder"], None]) -> None:
        """Run ``fn(builder)`` once at the start of :meth:`build` (cross-row work)."""
        if fn not in self._finalizers:
            self._finalizers.append(fn)

    def add_extra(self, asset: CloudAsset | None) -> None:
        """Add a fully built asset (Defender, Sentinel, Kubernetes objects, ...)."""
        if asset is not None:
            self._extra.append(asset)

    def draft(self, resource_id: str | None) -> _Draft | None:
        return self._drafts.get(resource_id.lower()) if resource_id else None

    def drafts_of(self, *types: str) -> list[_Draft]:
        """Drafts of the given lowercase ARM types, in insertion order."""
        wanted = {t.lower() for t in types}
        return [d for d in self._drafts.values() if d.type in wanted]

    @property
    def drafts(self) -> list[_Draft]:
        return list(self._drafts.values())

    @property
    def extras(self) -> list[CloudAsset]:
        return list(self._extra)

    # ── input ──

    def add_rows(self, rows: Iterable[dict[str, Any]], discovered_via: str | None = None) -> None:
        for row in rows:
            try:
                self.add_row(row, discovered_via=discovered_via)
            except Exception:
                logger.debug("Skipping Azure row %s", (row or {}).get("id"), exc_info=True)

    def add_row(
        self,
        row: dict[str, Any],
        *,
        synthetic: bool = False,
        discovered_via: str | None = None,
        vnet_id: str | None = None,
    ) -> _Draft | None:
        if not isinstance(row, dict):
            return None
        rid = row.get("id")
        rtype = _lower(row.get("type"))
        if not rid or not rtype:
            return None
        name = row.get("name") or rid.rstrip("/").rsplit("/", 1)[-1]
        if rtype == "microsoft.sql/servers/databases" and str(name).lower() == "master":
            return None
        if rtype == "microsoft.resources/subscriptions":
            self._subscription_row = row
            return None
        handler = _ROW_HANDLERS.get(rtype)
        if handler is not None:
            try:
                handler(row, self)
            except Exception:
                logger.debug("Azure row handler failed for %s", rid, exc_info=True)
            return None
        key = rid.lower()
        existing = self._drafts.get(key)
        has_props = isinstance(row.get("properties"), dict)
        if existing is not None and (not has_props or existing.props):
            return existing  # first detailed copy wins
        draft = self._new_draft(row, rid, rtype, str(name), synthetic)
        draft.md = self._base_metadata(row, discovered_via, has_props, synthetic)
        if vnet_id:
            draft.md["vnet_id"] = vnet_id
        self._drafts[key] = draft
        self._extract(draft)
        return draft

    def _new_draft(
        self, row: dict[str, Any], rid: str, rtype: str, name: str, synthetic: bool
    ) -> _Draft:
        props = row.get("properties") if isinstance(row.get("properties"), dict) else {}
        account = row.get("subscriptionId") or subscription_of(rid) or self.subscription_id
        return _Draft(
            row=row,
            id=rid,
            type=rtype,
            name=name,
            props=dict(props),
            asset_type=asset_type_from_arm(rtype, row.get("kind")),
            region=row.get("location") or "global",
            account_id=account,
            tags=_tags(row.get("tags")),
            synthetic=synthetic,
        )

    def _base_metadata(
        self,
        row: dict[str, Any],
        discovered_via: str | None,
        has_props: bool,
        synthetic: bool,
    ) -> dict[str, Any]:
        """Metadata every Azure asset carries, before the extractors run."""
        sku = row.get("sku")
        md: dict[str, Any] = {
            "resource_type": row.get("type"),
            "kind": row.get("kind"),
            "sku": _get(sku, "name") if isinstance(sku, dict) else sku,
            "resource_group": row.get("resourceGroup") or resource_group_name(row.get("id")),
            "collected_via": discovered_via or self.discovered_via,
        }
        if discovered_via == "arm-sweep" or (not has_props and not synthetic):
            md["discovered_via"] = "arm-sweep"
        if row.get("zones"):
            md["zones"] = row.get("zones")
        if row.get("plan"):
            md["plan"] = row.get("plan")
        return md

    def _extract(self, draft: _Draft) -> None:
        """Run the common extractors, then the ones registered for the type."""
        for fn in _COMMON + _EXTRACTORS.get(draft.type, []):
            try:
                fn(draft, self)
            except Exception:
                logger.debug(
                    "Azure extractor %s failed for %s", fn.__name__, draft.id, exc_info=True
                )

    def add_containers(self, rows: Iterable[dict[str, Any]]) -> None:
        """Resource groups (and the subscription row) of ``resourcecontainers``."""
        self._with_subscription = True
        for row in rows:
            rtype = _lower((row or {}).get("type"))
            if rtype == "microsoft.resources/subscriptions":
                self._subscription_row = row
            elif rtype in (
                "microsoft.resources/subscriptions/resourcegroups",
                "microsoft.resources/resourcegroups",
            ):
                row = dict(row)
                row["type"] = "microsoft.resources/subscriptions/resourcegroups"
                self.add_row(row, discovered_via=self.discovered_via)

    def include_subscription(self, row: dict[str, Any] | None = None) -> None:
        self._with_subscription = True
        if row:
            self._subscription_row = row

    def add_role_assignments(
        self,
        rows: Iterable[dict[str, Any]],
        *,
        eligible: bool = False,
        inherited_from: str | None = None,
    ) -> None:
        """RBAC role assignment rows (ARG ``authorizationresources`` or ARM REST).

        Args:
            eligible: The rows are PIM eligibility schedules, not active grants.
            inherited_from: Label for assignments made above the subscription
                (management group or tenant root).
        """
        for r in rows:
            if not isinstance(r, dict):
                continue
            if eligible or inherited_from:
                r = dict(r)
                r["_eligible"] = eligible
                r["_inherited_from"] = inherited_from
            self._role_rows.append(r)

    def add_role_definitions(self, rows: Iterable[dict[str, Any]]) -> None:
        """Role definition rows; assigned and custom ones become IAM_POLICY assets."""
        for row in rows:
            if not isinstance(row, dict):
                continue
            if _lower(row.get("type")) != "microsoft.authorization/roledefinitions":
                continue
            m = _GUID_TAIL_RE.search(str(row.get("id") or ""))
            guid = str(row.get("roleGuid") or (m.group(1) if m else "") or "").lower()
            if guid:
                self._role_definitions.setdefault(guid, row)

    def add_defender_pricings(self, rows: Iterable[dict[str, Any]]) -> None:
        sub_ref = subscription_ref(self.subscription_id)
        self._pricings_seen = True
        for row in rows:
            if not isinstance(row, dict):
                continue
            if _lower(row.get("type")) not in ("", "microsoft.security/pricings"):
                continue
            props = row.get("properties") or {}
            plan = row.get("name") or str(row.get("id", "")).rsplit("/", 1)[-1]
            if not plan:
                continue
            resource = _pricing_resource(row.get("id"))
            if resource:  # a resource-level override of a subscription plan
                self._pricing_overrides[f"{resource.lower()}|{plan.lower()}"] = (
                    _lower(_get(props, "pricingTier")) == "standard"
                )
                continue
            tier = _get(props, "pricingTier")
            enabled = _lower(tier) == "standard"
            service = f"defender-{plan.lower()}"
            md: dict[str, Any] = {
                "security_service": service,
                "enabled": enabled,
                "pricing_tier": tier,
                "sub_plan": _get(props, "subPlan"),
                "resource_type": "microsoft.security/pricings",
                "aliases": [f"azure-security:{service}:{self.subscription_id}"],
            }
            if enabled:
                md["relations"] = [
                    rel(
                        sub_ref,
                        EdgeType.MONITORS,
                        "MONITORED_BY",
                        description=f"Defender for Cloud plan {plan}",
                    )
                ]
                extensions = [e for e in _get(props, "extensions") or [] if isinstance(e, dict)]
                if extensions:
                    md["extensions"] = [
                        {"name": _get(e, "name"), "enabled": _get(e, "isEnabled")}
                        for e in extensions
                    ]
            else:
                md["status"] = "not enabled"
            self._extra.append(
                CloudAsset(
                    arn=row.get("id") or f"{sub_ref}/providers/Microsoft.Security/pricings/{plan}",
                    name=f"Defender for Cloud: {plan}" + ("" if enabled else " (not enabled)"),
                    asset_type=AssetType.THREAT_DETECTOR,
                    provider=CloudProvider.AZURE,
                    region="global",
                    account_id=self.subscription_id,
                    metadata=md,
                )
            )

    # ── output ──

    def _role_assignments(self) -> None:
        placeholders: dict[str, CloudAsset] = {}
        registries = [
            d for d in self._drafts.values() if d.type == "microsoft.containerregistry/registries"
        ]
        for ra in self._role_rows:
            props = ra.get("properties") or {}
            pid = ra.get("principalId") or _get(props, "principalId")
            if not pid:
                continue
            ptype = ra.get("principalType") or _get(props, "principalType")
            scope = normalize_scope(ra.get("scope") or _get(props, "scope"))
            guid, relation = _role_relation(ra, props, scope, ptype)
            self.note_principal(pid, ptype)
            self._attach_principal_relation(pid, ptype, relation, placeholders)
            # AKS kubelet identity with AcrPull -> the cluster pulls from the registry
            if guid == ACR_PULL_ROLE_ID and pid.lower() in self._kubelets and scope:
                self._kubelet_acr_pull(pid, scope, registries)
        # role definition attachments (ROLE/USER/GROUP_HAS_POLICY), when definitions were read
        for pid, ptype, relation in self.state.get("role_attachments", []):
            self._attach_principal_relation(pid, ptype, relation, placeholders)
        self._extra.extend(placeholders.values())
        # principals referenced elsewhere (Key Vault policies, SQL admins) without an owner
        for key, ptype in self._principal_types.items():
            if key in placeholders or key in self._principal_owner:
                continue
            self._extra.append(self._placeholder(key, ptype))

    def _attach_principal_relation(
        self,
        pid: str,
        ptype: str | None,
        relation: dict[str, Any] | None,
        placeholders: dict[str, CloudAsset],
    ) -> None:
        """Hang a role grant on the principal's owning asset, else on a placeholder."""
        owner = self._principal_owner.get(pid.lower())
        if owner and owner in self._drafts:
            self._drafts[owner].add(relation)
            return
        ph = placeholders.get(pid.lower()) or self._placeholder(pid, ptype)
        placeholders[pid.lower()] = ph
        if relation:
            ph.metadata.setdefault("relations", []).append(relation)

    def _kubelet_acr_pull(self, pid: str, scope: str, registries: list[_Draft]) -> None:
        sl = scope.lower()
        targets = [
            r.id for r in registries if r.id.lower() == sl or r.id.lower().startswith(sl + "/")
        ]
        if not targets and "/providers/microsoft.containerregistry/registries/" in sl:
            targets = [scope]
        for aks_id in self._kubelets[pid.lower()]:
            for reg in targets:
                self.defer(
                    aks_id,
                    rel(
                        reg,
                        EdgeType.USES_IMAGE,
                        "RUNS_ON",
                        description="kubelet identity has AcrPull",
                        via="AcrPull",
                    ),
                )

    def _placeholder(self, principal_id: str, principal_type: str | None) -> CloudAsset:
        ptl = _lower(principal_type)
        if ptl == "user":
            asset_type = AssetType.IDENTITY_USER
        elif ptl == "group":
            asset_type = AssetType.IDENTITY_GROUP
        else:
            asset_type = AssetType.SERVICE_PRINCIPAL
        label = principal_type or "principal"
        return CloudAsset(
            arn=principal_ref(principal_id),
            name=f"Entra {label} {principal_id.lower()}",
            asset_type=asset_type,
            provider=CloudProvider.AZURE,
            region="global",
            account_id=None,
            metadata={
                "principal_id": principal_id.lower(),
                "principal_type": principal_type or "Unknown",
                "placeholder": True,
                "discovered_via": "entra-principal-reference",
            },
        )

    def _subscription_asset(self) -> CloudAsset:
        row = self._subscription_row or {}
        props = row.get("properties") or {}
        sub = self.subscription_id
        display = (
            row.get("name")
            if row.get("name") and row.get("name") != sub
            else _get(props, "displayName")
        )
        return CloudAsset(
            arn=subscription_ref(sub),
            name=display or f"subscription {sub}",
            asset_type=AssetType.CLOUD_ACCOUNT,
            provider=CloudProvider.AZURE,
            region="global",
            account_id=sub,
            tags=_tags(row.get("tags")),
            metadata={
                "account_id": sub,
                "subscription_id": sub,
                "display_name": display,
                "state": _get(props, "state"),
                "tenant_id": row.get("tenantId"),
                "discovered_via": "azure-subscription",
            },
        )

    def build(self) -> list[CloudAsset]:
        """Finalize: build hooks, role assignments, deferred relations, then CloudAssets."""
        from cloudg.inventory.azure_graph.governance import role_definition_assets
        from cloudg.inventory.azure_graph.security import defender_coverage

        for fn in list(self._finalizers):
            try:
                fn(self)
            except Exception:
                logger.debug("Azure build hook %s failed", fn, exc_info=True)
        defender_coverage(self, self._pricing_overrides, self._pricings_seen)
        if self._role_definitions:
            role_definition_assets(self, self._role_definitions, self._role_rows)
        self._role_assignments()
        for owner, relation in self._deferred:
            draft = self._drafts.get(owner)
            if draft is not None:
                draft.add(relation)
        assets: list[CloudAsset] = []
        if self._with_subscription:
            assets.append(self._subscription_asset())
        assets.extend(_draft_asset(d) for d in self._drafts.values())
        assets.extend(self._extra)
        return assets


def build_assets(
    rows: Iterable[dict[str, Any]],
    subscription_id: str,
    discovered_via: str = "resource-graph",
) -> list[CloudAsset]:
    """Convenience: rows of one subscription -> linked CloudAssets."""
    builder = AzureAssetBuilder(subscription_id, discovered_via)
    builder.add_rows(rows)
    return builder.build()


def collect_subscription_graph(
    client: Any,
    subscription_id: str,
    *,
    role_assignments: bool = True,
    defender: bool = True,
    errors: dict[str, str] | None = None,
    tasks: Iterable[str] | None = None,
    recorder: Any = None,
    keep_row: Callable[[dict[str, Any]], bool] | None = None,
) -> AzureAssetBuilder:
    """Query ARG for one subscription and return a populated builder.

    The ``resources`` query must succeed (its exception propagates so the
    caller can fall back to the SDK path); the container, role-assignment
    and Defender queries are best-effort and record failures in ``errors``.
    The other Resource Graph tables (policy, security, backup, Kubernetes
    configuration, network manager, guest configuration, maintenance,
    insights) and the management-group role assignments and role
    definitions are best-effort too: their failures become FAILED coverage
    records on ``recorder``.

    Args:
        tasks: Task names to run (:mod:`.families`); None runs every task.
        recorder: :class:`~.families.TaskRecorder` for per-task coverage.
        keep_row: Predicate filtering the ``resources`` rows (``--services``).
    """
    from cloudg.inventory.azure_graph.families import TaskRecorder
    from cloudg.inventory.azure_graph.tables import collect_tables

    errors = errors if errors is not None else {}
    rec = recorder if recorder is not None else TaskRecorder()
    selected = set(tasks) if tasks is not None else None

    def on(task: str) -> bool:
        if selected is None or task in selected:
            return True
        rec.skip(task, "not selected (inventory.services)")
        return False

    subs = [subscription_id]
    builder = AzureAssetBuilder(subscription_id, "resource-graph")
    started = time.time()
    resource_rows = run_query(client, resources_query(subscription_id), subscriptions=subs)
    if keep_row is not None:
        resource_rows = [r for r in resource_rows if keep_row(r)]
    builder.add_rows(resource_rows)
    rec.record("resources", "SUCCESS", len(resource_rows), started=started)
    builder.include_subscription()
    started = time.time()
    container_rows: list[dict[str, Any]] = []
    try:
        container_rows = run_query(client, containers_query(subscription_id), subscriptions=subs)
        builder.add_containers(container_rows)
        rec.record("resource_containers", "SUCCESS", len(container_rows), started=started)
    except Exception as exc:
        errors["resource_graph_containers"] = str(exc)
    if role_assignments and on("role_assignments"):
        started = time.time()
        try:
            rows = run_query(client, role_assignments_query(subscription_id), subscriptions=subs)
            builder.add_role_assignments(rows)
            rec.record("role_assignments", "SUCCESS", len(rows), started=started)
        except Exception as exc:
            errors["resource_graph_role_assignments"] = str(exc)
    if defender and on("defender_pricings"):
        started = time.time()
        try:
            rows = run_query(client, defender_query(subscription_id), subscriptions=subs)
            builder.add_defender_pricings(rows)
            rec.record("defender_pricings", "SUCCESS", len(rows), started=started)
        except Exception as exc:
            errors["resource_graph_defender"] = str(exc)
    collect_tables(
        client,
        builder,
        subscription_id,
        on=on,
        recorder=rec,
        container_rows=container_rows,
        role_assignments=role_assignments,
    )
    return builder
