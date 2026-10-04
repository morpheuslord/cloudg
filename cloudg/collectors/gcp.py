"""GCP resource collector built on the Cloud Asset Inventory API.

Enumeration uses ``AssetService.ListAssets`` with ``content_type=RESOURCE``
at project scope, or once at organization scope (``organizations/<id>``),
which returns the full resource JSON (``resource.data``) plus the resource
hierarchy (``ancestors``) for every supported asset type. Per-type
extractors in :mod:`cloudg.inventory.gcp_relations` turn that JSON into
typed relations, exposure flags and metadata.

If ``ListAssets`` is denied, the collector falls back to
``SearchAllResources`` (summary fields only) and records the run as
PARTIAL; if both fail it raises so the orchestrator records FAILED.
Blocking gRPC calls run in worker threads, with retries on quota and
availability errors.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import defaultdict
from typing import Any, Iterable

from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.collectors.base import BaseCollector
from cloudg.coverage import CollectionCoverage, ServiceStatus
from cloudg.schema.models import (
    AssetType,
    CloudAsset,
    CloudProvider,
    EdgeType,
    NetworkEdge,
)

logger = logging.getLogger(__name__)

# Mapping from GCP asset types to our normalised AssetType
# Asset type -> AssetType; the table lives in catalogs/gcp_asset_types.yaml.
_GCP_ASSET_TYPE_MAP: dict[str, AssetType] = asset_type_map(
    load_catalog("gcp_asset_types").get("base"), "gcp_asset_types"
)

# High-churn types skipped unless configured otherwise (GCPConfig.skip_asset_types)
DEFAULT_SKIP_ASSET_TYPES: tuple[str, ...] = (
    "k8s.io/Pod",
    "k8s.io/Node",
    "k8s.io/Event",
    "events.k8s.io/Event",
    "k8s.io/Endpoints",
    "discovery.k8s.io/EndpointSlice",
    "apps.k8s.io/ReplicaSet",
    "apps.k8s.io/ControllerRevision",
    "run.googleapis.com/Revision",
    "cloudkms.googleapis.com/CryptoKeyVersion",
    "secretmanager.googleapis.com/SecretVersion",
    "serviceusage.googleapis.com/Service",
)

_RESOURCE_MANAGER = "//cloudresourcemanager.googleapis.com/"
_PROJECT_SEG_RE = re.compile(r"/projects/([^/]+)/")


def _project_segment(name: str) -> str | None:
    m = _PROJECT_SEG_RE.search(name + "/")
    seg = m.group(1) if m else None
    return seg if seg not in (None, "_", "-") else None


_INTERNET = "0.0.0.0/0"


def to_plain(obj: Any) -> Any:
    """Convert proto-plus / raw protobuf / plain objects into dicts."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, (list, tuple)):
        return [to_plain(i) for i in obj]
    cls = type(obj)
    if hasattr(cls, "to_dict") and hasattr(cls, "meta"):
        return cls.to_dict(obj)
    if hasattr(obj, "DESCRIPTOR"):
        from google.protobuf.json_format import MessageToDict

        return MessageToDict(obj, preserving_proto_field_name=True)
    if hasattr(obj, "__dict__"):
        return {k: to_plain(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return obj


def state_str(value: Any) -> str | None:
    """Resource state as a string; the CAI API returns plain strings, older
    clients and tests may hand back enum-like objects."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return value
    name = getattr(value, "name", None)
    return name if isinstance(name, str) else str(value)


def _content_type(name: str) -> Any:
    try:
        from google.cloud import asset_v1

        return asset_v1.ContentType[name]
    except Exception:  # SDK missing (injected test client)
        return name


def _retry() -> Any:
    try:
        from google.api_core import exceptions as gexc
        from google.api_core import retry as retries
    except ImportError:
        return None
    return retries.Retry(
        predicate=retries.if_exception_type(
            gexc.ResourceExhausted,
            gexc.ServiceUnavailable,
            gexc.DeadlineExceeded,
            gexc.InternalServerError,
        ),
        initial=1.0,
        maximum=60.0,
        multiplier=2.0,
        timeout=900.0,
    )


def _num(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


class GCPCollector(BaseCollector):
    """Collects GCP resources using the Cloud Asset Inventory API.

    Args:
        project_id: Project to collect (also the fallback account id).
        credentials: google-auth credentials.
        organization_id: Collect once at ``organizations/<id>`` scope instead
            of the project (covers every project in the org).
        scope: Explicit CAI scope (``projects/x``, ``folders/y``, ...).
        project_filter: At org/folder scope, keep only these projects (IDs
            or numbers); org- and folder-level resources are always kept.
        skip_asset_types: CAI types to drop (high-churn Kubernetes objects...).
        page_size: ListAssets page size (max 1000).
        include_iam: Collect IAM policy bindings (deep collector).
        client: Injected ``AssetServiceClient`` (tests).
        coverage: Coverage record that receives per-API status.
        timeout: Per-call timeout in seconds.
        link_locally: Resolve relations into edges in :meth:`collect_edges`
            (for pipelines that do not run the inventory linker).
    """

    supports_org_scope = True
    _link_locally_default = True

    def __init__(
        self,
        project_id: str | None,
        credentials: Any = None,
        *,
        organization_id: str | None = None,
        scope: str | None = None,
        project_filter: Iterable[str] | None = None,
        skip_asset_types: Iterable[str] | None = None,
        page_size: int = 1000,
        include_iam: bool = True,
        client: Any = None,
        coverage: CollectionCoverage | None = None,
        timeout: float = 600.0,
        link_locally: bool | None = None,
    ) -> None:
        self._project_id = project_id
        self._credentials = credentials
        org = str(organization_id).removeprefix("organizations/") if organization_id else None
        self._organization_id = org
        if scope:
            self._scope = scope
        elif org:
            self._scope = f"organizations/{org}"
        else:
            self._scope = f"projects/{project_id}"
        self._project_scope = self._scope.startswith("projects/")
        self._project_filter = {str(p) for p in project_filter or []}
        self._skip_types = set(DEFAULT_SKIP_ASSET_TYPES if skip_asset_types is None else skip_asset_types)
        self._page_size = max(1, min(int(page_size), 1000))
        self._include_iam = include_iam
        self._client = client
        self.coverage = coverage or CollectionCoverage(provider="gcp", account_id=self._scope)
        self._timeout = timeout
        self._link_locally = self._link_locally_default if link_locally is None else link_locally
        self._cached_assets: list[CloudAsset] = []
        self._collected = False
        self._number_to_id: dict[str, str] = {}
        self._id_to_number: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_asset_type(self, gcp_type: str) -> AssetType:
        """Map GCP asset type string to normalised AssetType."""
        return _GCP_ASSET_TYPE_MAP.get(gcp_type, AssetType.OTHER)

    def _extract_location(self, name: str) -> str:
        """Extract region/zone from resource name."""
        parts = name.split("/")
        for i, part in enumerate(parts):
            if part in ("zones", "regions", "locations") and i + 1 < len(parts):
                return parts[i + 1]
        return "global"

    def _record(self, service: str, status: ServiceStatus, count: int = 0, error: str | None = None, start: float | None = None) -> None:
        duration = int((time.time() - start) * 1000) if start else None
        self.coverage.record(service, status, asset_count=count, error=error, duration_ms=duration)

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from google.cloud import asset_v1
            except ImportError as exc:
                raise RuntimeError(
                    "google-cloud-asset is not installed; install cloudg[gcp] to collect GCP"
                ) from exc
            self._client = asset_v1.AssetServiceClient(credentials=self._credentials)
        return self._client

    def _call_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        retry = _retry()
        if retry is not None:
            kwargs["retry"] = retry
        return kwargs

    def _iterate(self, method: Any, request: dict[str, Any]) -> tuple[list[dict[str, Any]], Exception | None]:
        """Drain a paged CAI call in the calling (worker) thread."""
        items: list[dict[str, Any]] = []
        try:
            for item in method(request=request, **self._call_kwargs()):
                items.append(to_plain(item))
        except Exception as exc:
            return items, exc
        return items, None

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _list_assets(
        self, content_type: str, asset_types: list[str] | None = None
    ) -> tuple[list[dict[str, Any]], Exception | None]:
        client = self._get_client()
        request: dict[str, Any] = {
            "parent": self._scope,
            "content_type": _content_type(content_type),
            "page_size": self._page_size,
        }
        if asset_types:
            request["asset_types"] = asset_types
        return self._iterate(client.list_assets, request)

    def _search_resources(self) -> tuple[list[dict[str, Any]], Exception | None]:
        client = self._get_client()
        request = {"scope": self._scope, "page_size": 500, "read_mask": "*"}
        return self._iterate(client.search_all_resources, request)

    @staticmethod
    def _record_from_asset(d: dict[str, Any]) -> dict[str, Any]:
        res = d.get("resource") or {}
        return {
            "name": d.get("name") or "",
            "asset_type": d.get("asset_type") or d.get("assetType") or "",
            "data": res.get("data") or {},
            "location": res.get("location") or "",
            "parent": res.get("parent") or "",
            "ancestors": list(d.get("ancestors") or []),
            "update_time": d.get("update_time") or d.get("updateTime"),
        }

    @staticmethod
    def _record_from_search(d: dict[str, Any]) -> dict[str, Any]:
        """A SearchAllResources result in the ListAssets record shape (summary only)."""

        def g(snake: str, camel: str) -> Any:
            return d.get(snake, d.get(camel))

        project = g("project", "project") or ""
        ancestors = [project] if project else []
        ancestors += list(g("folders", "folders") or [])
        if g("organization", "organization"):
            ancestors.append(g("organization", "organization"))
        return {
            "name": d.get("name") or "",
            "asset_type": g("asset_type", "assetType") or "",
            "data": {},
            "location": d.get("location") or "",
            "parent": g("parent_full_resource_name", "parentFullResourceName") or "",
            "ancestors": ancestors,
            "summary": {
                "display_name": g("display_name", "displayName"),
                "description": d.get("description"),
                "state": state_str(d.get("state")),
                "labels": dict(d.get("labels") or {}),
                "network_tags": list(g("network_tags", "networkTags") or []),
                "kms_keys": list(g("kms_keys", "kmsKeys") or []),
                "create_time": g("create_time", "createTime"),
                "parent_asset_type": g("parent_asset_type", "parentAssetType"),
            },
        }

    async def _collect_records(self) -> list[dict[str, Any]]:
        start = time.time()
        raw, error = await asyncio.to_thread(self._list_assets, "RESOURCE")
        if error is None:
            self._record("gcp_list_assets", ServiceStatus.SUCCESS, len(raw), start=start)
            return [self._record_from_asset(r) for r in raw]
        if raw:
            logger.error("GCP ListAssets for %s stopped after %d assets: %s", self._scope, len(raw), error)
            self._record(
                "gcp_list_assets", ServiceStatus.PARTIAL, len(raw), f"listing truncated: {error}", start=start
            )
            return [self._record_from_asset(r) for r in raw]

        logger.warning("GCP ListAssets failed for %s (%s); falling back to SearchAllResources", self._scope, error)
        search_start = time.time()
        found, search_error = await asyncio.to_thread(self._search_resources)
        if search_error is not None and not found:
            self._record("gcp_list_assets", ServiceStatus.FAILED, error=str(error), start=start)
            self._record("gcp_search_resources", ServiceStatus.FAILED, error=str(search_error), start=search_start)
            raise RuntimeError(
                f"GCP asset enumeration failed for {self._scope}: ListAssets: {error}; "
                f"SearchAllResources: {search_error}"
            )
        self._record("gcp_list_assets", ServiceStatus.FAILED, error=str(error), start=start)
        self._record(
            "gcp_search_resources",
            ServiceStatus.PARTIAL,
            len(found),
            "summary data only (ListAssets unavailable)"
            + (f"; listing truncated: {search_error}" if search_error else ""),
            start=search_start,
        )
        return [self._record_from_search(r) for r in found]

    # ------------------------------------------------------------------
    # Project number <-> id
    # ------------------------------------------------------------------

    def _learn_projects(self, records: list[dict[str, Any]]) -> None:
        for rec in records:
            data = rec.get("data") or {}
            if rec["asset_type"] == "cloudresourcemanager.googleapis.com/Project":
                number = _num(data.get("projectNumber"))
                if not number and str(data.get("name", "")).startswith("projects/"):
                    number = data["name"].split("/", 1)[1]
                if not number:
                    number = rec["name"].rsplit("/", 1)[-1]
                pid = data.get("projectId")
                if number and pid:
                    self._number_to_id.setdefault(number, pid)
        for rec in records:
            number = self._ancestor_number(rec)
            if not number or number in self._number_to_id:
                continue
            seg = _project_segment(rec["name"])
            if seg and not seg.isdigit():
                self._number_to_id[number] = seg
        if self._project_scope and self._project_id:
            numbers = {self._ancestor_number(r) for r in records} - {None}
            if len(numbers) == 1:
                self._number_to_id.setdefault(numbers.pop(), self._project_id)
        self._id_to_number = {v: k for k, v in self._number_to_id.items()}

    @staticmethod
    def _ancestor_number(rec: dict[str, Any]) -> str | None:
        for a in rec.get("ancestors") or []:
            if isinstance(a, str) and a.startswith("projects/"):
                return a.split("/", 1)[1]
        return None

    def _project_of(self, rec: dict[str, Any]) -> tuple[str | None, str | None]:
        """(project id, project number) of a record."""
        number = self._ancestor_number(rec)
        pid = self._number_to_id.get(number) if number else None
        if not pid:
            seg = _project_segment(rec["name"])
            if seg and not seg.isdigit():
                pid = seg
            elif seg:
                number = number or seg
                pid = self._number_to_id.get(seg)
        if not pid and self._project_scope:
            pid = self._project_id
        if pid and not number:
            number = self._id_to_number.get(pid)
        return pid, number

    def _keep(self, rec: dict[str, Any], pid: str | None, number: str | None) -> bool:
        if rec["asset_type"] in self._skip_types:
            return False
        if self._project_filter and (pid or number):
            return bool({pid, number} & self._project_filter)
        return True

    # ------------------------------------------------------------------
    # Asset building
    # ------------------------------------------------------------------

    @staticmethod
    def _display_name(rec: dict[str, Any], data: dict[str, Any]) -> str:
        atype = rec["asset_type"]
        if atype == "iam.googleapis.com/ServiceAccount" and data.get("email"):
            return str(data["email"])
        if atype == "cloudresourcemanager.googleapis.com/Project" and data.get("projectId"):
            return str(data["projectId"])
        if atype == "compute.googleapis.com/Project":
            return f"compute settings ({data.get('name') or rec['name'].rsplit('/', 1)[-1]})"
        for key in ("displayName", "display_name"):
            if isinstance(data.get(key), str) and data[key]:
                return data[key]
        meta_name = (data.get("metadata") or {}).get("name") if isinstance(data.get("metadata"), dict) else None
        if isinstance(meta_name, str) and meta_name:
            return meta_name
        name = data.get("name")
        if isinstance(name, str) and name:
            return name.rsplit("/", 1)[-1]
        summary = rec.get("summary") or {}
        if summary.get("display_name"):
            return str(summary["display_name"])
        return rec["name"].rstrip("/").rsplit("/", 1)[-1] or rec["name"]

    def _number_id_aliases(self, name: str) -> list[str]:
        out = []
        m = re.search(r"/projects/([^/]+)(/|$)", name)
        if not m:
            return out
        seg = m.group(1)
        other = self._number_to_id.get(seg) if seg.isdigit() else self._id_to_number.get(seg)
        if other:
            out.append(name[: m.start(1)] + other + name[m.end(1):])
        return out

    def _build_asset(self, rec: dict[str, Any]) -> CloudAsset | None:
        from cloudg.inventory.gcp_relations import GCPContext, extract, full_name, mark_exposed, scrub

        pid, number = self._project_of(rec)
        if not self._keep(rec, pid, number):
            return None
        name = rec["name"]
        atype = rec["asset_type"]
        data = scrub(rec.get("data") or {})
        summary = rec.get("summary") or {}
        ancestors = rec.get("ancestors") or []
        location = rec.get("location") or data.get("region") or data.get("zone") or self._extract_location(name)
        if isinstance(location, str) and "/" in location:
            location = location.rsplit("/", 1)[-1]

        ctx = GCPContext(
            name=name,
            asset_type=atype,
            data=data,
            project_id=pid,
            project_number=number,
            location=location if location != "global" else None,
            ancestors=list(ancestors),
        )
        ex = extract(ctx)

        labels = data.get("labels")
        if not isinstance(labels, dict) and isinstance(data.get("metadata"), dict):
            labels = data["metadata"].get("labels")
        if not isinstance(labels, dict):
            labels = summary.get("labels") or {}
        state = None
        for key in ("status", "state", "lifecycleState"):
            if isinstance(data.get(key), str):
                state = data[key]
                break
        state = state or summary.get("state")
        description = data.get("description") or summary.get("description")
        if isinstance(description, str) and len(description) > 500:
            description = description[:500]

        metadata: dict[str, Any] = {
            "gcp_asset_type": atype,
            "project": pid,
            "project_id": pid,
            "project_number": number,
            "folders": [a for a in ancestors if isinstance(a, str) and a.startswith("folders/")],
            "organization": next((a for a in ancestors if isinstance(a, str) and a.startswith("organizations/")), None),
            "location": location,
            "state": state,
            "create_time": data.get("creationTimestamp") or data.get("createTime") or data.get("timeCreated") or summary.get("create_time"),
            "description": description,
            "parent_full_resource_name": rec.get("parent") or None,
            "parent_asset_type": summary.get("parent_asset_type"),
            "network_tags": summary.get("network_tags") or [],
        }
        if summary.get("kms_keys"):
            metadata["kms_keys"] = [full_name(k, "cloudkms") or k for k in summary["kms_keys"]]
        metadata.update({k: v for k, v in ex.metadata.items() if v is not None})
        if ex.relations:
            metadata["relations"] = ex.relations
        aliases = list(ex.aliases)
        self_link = full_name(data.get("selfLink"))
        for alias in [self_link, *self._number_id_aliases(name)]:
            if alias and alias != name and alias not in aliases:
                aliases.append(alias)
        if aliases:
            metadata["aliases"] = aliases
        if summary:
            metadata["summary_only"] = True

        account_id = pid
        if atype in ("cloudresourcemanager.googleapis.com/Organization", "cloudresourcemanager.googleapis.com/Folder"):
            account_id = None
        asset = CloudAsset(
            arn=name,
            name=self._display_name(rec, data),
            asset_type=self._resolve_asset_type(atype),
            provider=CloudProvider.GCP,
            region=location or "global",
            account_id=account_id,
            tags={str(k): str(v) for k, v in (labels or {}).items()},
            metadata=metadata,
            raw_data={"name": name, "asset_type": atype, "ancestors": list(ancestors), "data": data},
        )
        for entry in ex.exposure:
            mark_exposed(asset, entry["via"], kind=entry.get("kind"), protocol=entry.get("protocol"), ports=entry.get("ports"))
        return asset

    def _build_assets(self, records: list[dict[str, Any]]) -> list[CloudAsset]:
        self._learn_projects(records)
        assets: list[CloudAsset] = []
        failures: list[str] = []
        for rec in records:
            try:
                asset = self._build_asset(rec)
            except Exception as exc:
                failures.append(f"{rec.get('name')}: {type(exc).__name__}: {exc}")
                logger.debug("Failed to map GCP asset %s", rec.get("name"), exc_info=True)
                continue
            if asset is not None:
                assets.append(asset)
        if failures:
            self._record(
                "gcp_asset_mapping",
                ServiceStatus.PARTIAL,
                len(assets),
                f"{len(failures)} assets could not be mapped; first: {failures[0]}",
            )
        return assets

    # ------------------------------------------------------------------
    # Cross-asset passes
    # ------------------------------------------------------------------

    def _apply_firewalls(self, assets: list[CloudAsset]) -> None:
        """Attach VPC firewall rules to the instances they target and derive
        instance exposure (external IP + enabled 0.0.0.0/0 ingress allow)."""
        from cloudg.inventory.aws_services._base import rel
        from cloudg.inventory.gcp_relations import mark_exposed

        by_network: dict[str, list[CloudAsset]] = defaultdict(list)
        for a in assets:
            if a.metadata.get("gcp_asset_type") == "compute.googleapis.com/Firewall" and a.metadata.get("network"):
                by_network[a.metadata["network"]].append(a)

        for inst in assets:
            if inst.metadata.get("gcp_asset_type") != "compute.googleapis.com/Instance":
                continue
            tags = set(inst.metadata.get("network_tags") or [])
            sas = set(inst.metadata.get("service_account_emails") or [])
            nets = inst.metadata.get("networks") or []
            matched: list[CloudAsset] = []
            for net in nets:
                for fw in by_network.get(net, []):
                    md = fw.metadata
                    if md.get("disabled"):
                        continue
                    if md.get("target_service_accounts"):
                        hit = bool(sas & set(md["target_service_accounts"]))
                    elif md.get("target_tags"):
                        hit = bool(tags & set(md["target_tags"]))
                    else:
                        hit = True
                    if not hit:
                        continue
                    matched.append(fw)
                    r = rel(
                        fw.arn,
                        EdgeType.ATTACHED_TO,
                        "PROTECTED_BY_SG",
                        description=f"firewall rule {fw.name} applies to {inst.name}",
                        direction=md.get("direction"),
                        action=md.get("action"),
                        priority=md.get("priority"),
                    )
                    rels = inst.metadata.setdefault("relations", [])
                    if r and r not in rels:
                        rels.append(r)

            if not inst.metadata.get("public_ips"):
                continue
            denies = [
                f for f in matched
                if f.metadata.get("action") == "deny" and f.metadata.get("internet_source")
                and any(p.get("protocol") == "all" for p in (f.metadata.get("ingress_rules") or [{}])[0].get("protocols", []))
            ]
            best_deny = min((f.metadata.get("priority", 1000) for f in denies), default=None)
            open_rules = [
                f for f in matched
                if f.metadata.get("allows_internet_ingress")
                and (best_deny is None or f.metadata.get("priority", 1000) < best_deny)
            ]
            for fw in open_rules:
                for proto in (fw.metadata.get("ingress_rules") or [{}])[0].get("protocols", []):
                    mark_exposed(
                        inst,
                        f"external IP and firewall {fw.name} allows {_INTERNET}",
                        kind="SECURITY_GROUP_RULE",
                        protocol=proto.get("protocol"),
                        ports=proto.get("ports") or None,
                        firewall=fw.arn,
                    )
            if not open_rules and not any(by_network.get(n) for n in nets) and nets:
                mark_exposed(inst, "external IP; no firewall rules were collected for its network")

    def _ensure_project_asset(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        """Project scope: make sure the project itself is an asset (IAM
        bindings and parent containment point at it)."""
        if not self._project_scope or not self._project_id:
            return []
        for a in assets:
            if a.asset_type == AssetType.CLOUD_ACCOUNT and a.account_id == self._project_id:
                return []
        number = self._id_to_number.get(self._project_id)
        ident = number or self._project_id
        aliases = [f"projects/{self._project_id}", f"{_RESOURCE_MANAGER}projects/{self._project_id}", self._project_id]
        if number:
            aliases += [f"projects/{number}", number]
        return [
            CloudAsset(
                arn=f"{_RESOURCE_MANAGER}projects/{ident}",
                name=self._project_id,
                asset_type=AssetType.CLOUD_ACCOUNT,
                provider=CloudProvider.GCP,
                region="global",
                account_id=self._project_id,
                metadata={
                    "gcp_asset_type": "cloudresourcemanager.googleapis.com/Project",
                    "account_id": self._project_id,
                    "project_id": self._project_id,
                    "project_number": number,
                    "aliases": [a for a in aliases if a != f"{_RESOURCE_MANAGER}projects/{ident}"],
                    "discovered_via": "collection scope",
                },
            )
        ]

    async def _enrich(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        """Hook for subclasses: return extra assets (e.g. IAM principals)."""
        return []

    def _finalize(self, assets: list[CloudAsset]) -> list[CloudAsset]:
        from cloudg.inventory.gcp_relations import ensure_service_account_principals, merge_gcp_principals

        self._apply_firewalls(assets)
        assets = assets + self._ensure_project_asset(assets)
        assets = assets + ensure_service_account_principals(assets)
        assets, _ = merge_gcp_principals(assets)
        return assets

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def collect(self) -> list[CloudAsset]:
        """Collect all GCP assets via Cloud Asset Inventory.

        Raises:
            RuntimeError: If the SDK is missing or enumeration failed entirely.
        """
        logger.info("Starting GCP asset collection for %s", self._scope)
        records = await self._collect_records()
        assets = self._build_assets(records)
        assets = assets + await self._enrich(assets)
        assets = self._finalize(assets)
        logger.info("Collected %d GCP assets from %s", len(assets), self._scope)
        self._cached_assets = assets
        self._collected = True
        return assets

    async def collect_edges(self) -> list[NetworkEdge]:
        """Internet ingress edges (``0.0.0.0/0`` -> exposed asset), plus the
        locally resolved relation edges when ``link_locally`` is set."""
        assets = self._cached_assets if self._collected else await self.collect()
        edges: list[NetworkEdge] = []
        for a in assets:
            for entry in a.metadata.get("internet_ingress") or []:
                kind = entry.get("kind") or "INTERNET_EXPOSED"
                edge_type = EdgeType.SECURITY_GROUP_RULE if kind == "SECURITY_GROUP_RULE" else EdgeType.INTERNET_EXPOSED
                ports_raw = [str(p) for p in entry.get("ports") or []]
                ports: list[int] = []
                for p in ports_raw:
                    lo, _, hi = p.partition("-")
                    if lo.isdigit():
                        end = int(hi) if hi.isdigit() else int(lo)
                        ports.extend(range(int(lo), min(end, int(lo) + 99) + 1))
                proto = entry.get("protocol")
                edges.append(
                    NetworkEdge(
                        source_id=_INTERNET,
                        target_id=a.id,
                        edge_type=edge_type,
                        ports=ports[:100],
                        port_range=",".join(ports_raw) or None,
                        protocol=("ALL" if proto in (None, "all") else str(proto).upper()),
                        cidr=_INTERNET,
                        direction="ingress",
                        description=entry.get("via"),
                        relationship="INTERNET_REACHABLE",
                    )
                )
        if self._link_locally:
            from cloudg.inventory.linker import RelationshipLinker

            linker = RelationshipLinker(assets, materialize_external=False)
            linker.seed_existing(edges)
            edges.extend(linker.link(include_generic=False))
        logger.info("Collected %d GCP edges", len(edges))
        return edges
