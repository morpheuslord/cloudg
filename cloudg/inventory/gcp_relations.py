"""Relation extractors for GCP Cloud Asset Inventory resources.

Each extractor reads the full resource JSON that ``list_assets`` returns
(``resource.data``) for one CAI asset type and declares what the asset
talks to as ``metadata["relations"]`` entries built with :func:`rel`. The
:class:`~cloudg.inventory.linker.RelationshipLinker` later resolves the
targets against every collected asset and emits typed edges.

GCP references come in several shapes: compute selfLinks
(``https://www.googleapis.com/compute/v1/projects/p/...``), API URLs,
relative names (``projects/p/locations/l/...``), short names, and service
account emails. They are all normalised here, before they reach a
relation, to the CAI full resource name form
``//<service>.googleapis.com/<relative name>``, which is what the linker
treats as an identifier. Service accounts are referenced as
``serviceAccount:<email>`` (an alias on every service account asset).

Identity conventions:

- IAM principals that are not collected resources become assets with
  ``arn = "gcp-principal:<member>"`` (users, groups, domains, federated
  principals) so bindings never create ``is_external`` graph nodes.
- GKE workload identity Kubernetes service accounts use
  ``k8s-gke://<workload-pool-project>/<namespace>/<ksa>``.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

from cloudg.inventory.aws_services._base import rel
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType, NetworkEdge

logger = logging.getLogger(__name__)

PRINCIPAL_PREFIX = "gcp-principal:"
K8S_GKE_PREFIX = "k8s-gke://"
PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")
INTERNET_CIDRS = ("0.0.0.0/0", "::/0")

# Roles that let the member act as the service account they are granted on
IMPERSONATION_ROLES = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.workloadIdentityUser",
    "roles/iam.serviceAccountOpenIdTokenCreator",
}

SA_ASSET_TYPE = "iam.googleapis.com/ServiceAccount"

# ---------------------------------------------------------------------------
# Reference normalisation
# ---------------------------------------------------------------------------

_COMPUTE_URL_RE = re.compile(
    r"^https?://(?:www|compute)\.googleapis\.com/compute/(?:v1|beta|alpha|staging_v1)/(.+)$"
)
_STORAGE_URL_RE = re.compile(r"^https?://(?:www|storage)\.googleapis\.com/storage/v1/b/([^/?#]+)")
_API_URL_RE = re.compile(
    r"^https?://([a-z0-9-]+)\.googleapis\.com/(?:[a-z0-9_]+/)?v\d[a-z0-9]*/(.+)$"
)
_BARE_API_RE = re.compile(r"^([a-z0-9-]+)\.googleapis\.com/(.+)$")
_KEY_VERSION_RE = re.compile(r"/cryptoKeyVersions/[^/]+$")
_CRYPTO_KEY_RE = re.compile(
    r"(projects/[^/\s\"']+/locations/[^/\s\"']+/keyRings/[^/\s\"']+/cryptoKeys/[^/\s\"']+)"
)
_PROJECT_SEG_RE = re.compile(r"/projects/([^/]+)")
_AR_IMAGE_RE = re.compile(r"^([a-z0-9-]+)-docker\.pkg\.dev/([^/]+)/([^/]+)/")
_GCR_IMAGE_RE = re.compile(r"^((?:us|eu|asia)\.)?gcr\.io/([^/]+)/")
_KSA_MEMBER_RE = re.compile(r"^serviceAccount:([^\[]+)\.svc\.id\.goog\[([^/\]]+)/([^\]]+)\]$")
_KSA_PRINCIPAL_RE = re.compile(
    r"^principal://iam\.googleapis\.com/projects/[^/]+/locations/global/workloadIdentityPools/"
    r"([^/]+)\.svc\.id\.goog/subject/ns/([^/]+)/sa/([^/]+)$"
)
_POOL_RE = re.compile(
    r"^principal(?:Set)?://iam\.googleapis\.com/((?:projects/[^/]+/)?locations/global/"
    r"(?:workloadIdentityPools|workforcePools)/[^/]+)"
)

_SERVICE_ALIASES = {"sqladmin": "cloudsql"}

# (path fragment, CAI service) — first match wins for relative names
_RELATIVE_SERVICES: tuple[tuple[str, str], ...] = (
    ("/cryptoKeys/", "cloudkms"),
    ("/keyRings/", "cloudkms"),
    ("/secrets/", "secretmanager"),
    ("/topics/", "pubsub"),
    ("/subscriptions/", "pubsub"),
    ("/schemas/", "pubsub"),
    ("/repositories/", "artifactregistry"),
    ("/connectors/", "vpcaccess"),
    ("/functions/", "cloudfunctions"),
    ("/workflows/", "workflows"),
    ("/datasets/", "bigquery"),
    ("/serviceAccounts/", "iam"),
    ("/workloadIdentityPools/", "iam"),
    ("/triggers/", "eventarc"),
    ("/services/", "run"),
    ("/models/", "aiplatform"),
    ("/endpoints/", "aiplatform"),
    ("/apis/", "apigateway"),
    ("/hubs/", "networkconnectivity"),
    ("/spokes/", "networkconnectivity"),
    ("/deliveryPipelines/", "clouddeploy"),
    ("/targets/", "clouddeploy"),
    ("/buckets/", "logging"),
    ("/global/", "compute"),
    ("/regions/", "compute"),
    ("/zones/", "compute"),
)


def _guess_service(relative: str) -> str | None:
    if re.fullmatch(r"(projects|organizations|folders)/[^/]+", relative):
        return "cloudresourcemanager"
    for fragment, service in _RELATIVE_SERVICES:
        if fragment in relative:
            return service
    return None


def full_name(ref: Any, service: str | None = None) -> str | None:
    """Normalise any GCP reference to a CAI full resource name.

    Args:
        ref: selfLink / API URL, relative name, ``<svc>.googleapis.com/...``
            sink-style destination, ``gs://`` URL or full resource name.
        service: CAI service for relative names whose collection is
            ambiguous (e.g. ``container`` for ``projects/p/locations/l/clusters/c``).

    Returns:
        ``//<service>.googleapis.com/<relative>`` or None when the value is
        not a recognisable resource reference.
    """
    if not isinstance(ref, str):
        return None
    s = ref.strip()
    if not s:
        return None
    out: str | None = None
    if s.startswith("//"):
        out = s
    elif s.startswith("gs://"):
        bucket = s[5:].split("/", 1)[0]
        out = f"//storage.googleapis.com/{bucket}" if bucket else None
    elif s.startswith(("https://", "http://")):
        m = _COMPUTE_URL_RE.match(s)
        if m:
            out = f"//compute.googleapis.com/{m.group(1)}"
        elif (m := _STORAGE_URL_RE.match(s)) is not None:
            out = f"//storage.googleapis.com/{m.group(1)}"
        elif (m := _API_URL_RE.match(s)) is not None and m.group(1) != "www":
            svc = _SERVICE_ALIASES.get(m.group(1), m.group(1))
            out = f"//{svc}.googleapis.com/{m.group(2)}"
    elif (m := _BARE_API_RE.match(s)) is not None:
        svc = _SERVICE_ALIASES.get(m.group(1), m.group(1))
        rest = m.group(2)
        if svc == "logging" and re.fullmatch(r"projects/[^/]+", rest):
            out = f"//cloudresourcemanager.googleapis.com/{rest}"
        else:
            out = f"//{svc}.googleapis.com/{rest}"
    elif s.startswith("projects/_/buckets/"):
        out = f"//storage.googleapis.com/{s.split('/')[3]}"
    elif s.startswith(
        ("projects/", "organizations/", "folders/", "locations/", "apps/", "accessPolicies/")
    ):
        svc = service or _guess_service(s)
        out = f"//{svc}.googleapis.com/{s}" if svc else None
    if not out:
        return None
    out = out.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    out = _KEY_VERSION_RE.sub("", out)
    if out.startswith("//sqladmin.googleapis.com/"):
        out = "//cloudsql.googleapis.com/" + out[len("//sqladmin.googleapis.com/") :]
    if out.startswith("//container.googleapis.com/"):
        out = out.replace("/zones/", "/locations/")
    return out


def relative_name(name: str) -> str:
    """``//svc.googleapis.com/projects/p/x`` -> ``projects/p/x``."""
    if name.startswith("//"):
        parts = name[2:].split("/", 1)
        return parts[1] if len(parts) > 1 else ""
    return name


def project_of(name: str) -> str | None:
    m = _PROJECT_SEG_RE.search(name or "")
    return m.group(1) if m else None


def network_ref(value: Any, project: str | None) -> str | None:
    """Network as full name; short names are resolved in ``project``."""
    if not isinstance(value, str) or not value:
        return None
    if "/" in value:
        return full_name(value, "compute")
    if not project:
        return None
    return f"//compute.googleapis.com/projects/{project}/global/networks/{value}"


def subnet_ref(value: Any, project: str | None, region: str | None) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "/" in value:
        return full_name(value, "compute")
    if not project or not region:
        return None
    return f"//compute.googleapis.com/projects/{project}/regions/{region}/subnetworks/{value}"


def sa_email(ref: Any) -> str | None:
    """Service account email from an email, member string or resource name."""
    if not isinstance(ref, str):
        return None
    s = ref.strip()
    if s.startswith("serviceAccount:"):
        s = s[len("serviceAccount:") :]
    if "/serviceAccounts/" in s:
        s = s.rsplit("/serviceAccounts/", 1)[1]
    if "@" not in s or "[" in s:
        return None
    return s.lower()


def sa_ref(email: str) -> str:
    return f"serviceAccount:{email.lower()}"


def url_alias(url: Any) -> str | None:
    """``https://host`` for a URL (path and query dropped: they may carry tokens)."""
    if not isinstance(url, str) or "://" not in url:
        return None
    try:
        host = urlparse(url.strip()).hostname
    except ValueError:
        return None
    return f"https://{host.lower()}" if host else None


def image_repository(image: Any) -> str | None:
    """Artifact Registry repository for a container image reference."""
    if not isinstance(image, str) or not image:
        return None
    m = _AR_IMAGE_RE.match(image)
    if m:
        loc, proj, repo = m.groups()
        return (
            f"//artifactregistry.googleapis.com/projects/{proj}/locations/{loc}/repositories/{repo}"
        )
    m = _GCR_IMAGE_RE.match(image)
    if m:
        prefix, proj = m.groups()
        loc = {"us.": "us", "eu.": "europe", "asia.": "asia"}.get(prefix or "", "us")
        return f"//artifactregistry.googleapis.com/projects/{proj}/locations/{loc}/repositories/{prefix or ''}gcr.io"
    return None


def kms_refs(value: Any, limit: int = 20) -> list[str]:
    """Every Cloud KMS crypto key referenced anywhere inside ``value``."""
    found: list[str] = []

    def walk(v: Any, depth: int = 0) -> None:
        if depth > 12 or len(found) >= limit:
            return
        if isinstance(v, str):
            if "/cryptoKeys/" in v:
                for m in _CRYPTO_KEY_RE.findall(v):
                    ref = f"//cloudkms.googleapis.com/{m}"
                    if ref not in found:
                        found.append(ref)
        elif isinstance(v, dict):
            for item in v.values():
                walk(item, depth + 1)
        elif isinstance(v, (list, tuple)):
            for item in v:
                walk(item, depth + 1)

    walk(value)
    return found


def _num(value: Any) -> str | None:
    """Struct numbers arrive as floats; render integers without '.0'."""
    if value is None or value == "":
        return None
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def dig(d: Any, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
    return default if d is None else d


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


# ---------------------------------------------------------------------------
# Sensitive-value scrubbing
# ---------------------------------------------------------------------------

_REDACT_MAPS = {
    "environmentVariables",
    "buildEnvironmentVariables",
    "envVariables",
    "airflowConfigOverrides",
}
_REDACT_KEYS = {
    "sharedSecret",
    "sharedSecretHash",
    "privateKeyData",
    "privateKey",
    "rootPassword",
    "password",
    "clientKey",
    "clientSecret",
}
REDACTED = "<redacted>"


def scrub(data: Any) -> Any:
    """Copy of resource JSON with secret-bearing values removed.

    Environment variable values, instance / project metadata values
    (startup scripts, ssh keys), URL query strings, VPN shared secrets and
    key material never reach the inventory. Names and references are kept.
    """

    def walk(v: Any, key: str | None = None) -> Any:
        if isinstance(v, dict):
            out: dict[str, Any] = {}
            for k, item in v.items():
                if k in _REDACT_KEYS:
                    out[k] = REDACTED
                elif k in _REDACT_MAPS and isinstance(item, dict):
                    out[k] = {ek: REDACTED for ek in item}
                elif k == "env" and isinstance(item, list):
                    out[k] = [
                        {ek: ev for ek, ev in e.items() if ek != "value"}
                        if isinstance(e, dict)
                        else e
                        for e in item
                    ]
                elif (
                    k in ("metadata", "commonInstanceMetadata")
                    and isinstance(item, dict)
                    and isinstance(item.get("items"), list)
                ):
                    out[k] = {
                        **{mk: mv for mk, mv in item.items() if mk != "items"},
                        "items": [
                            {"key": e.get("key"), "value": REDACTED} if isinstance(e, dict) else e
                            for e in item["items"]
                        ],
                    }
                else:
                    out[k] = walk(item, k)
            return out
        if isinstance(v, list):
            return [walk(i, key) for i in v]
        if isinstance(v, str) and "://" in v and "?" in v and len(v) < 4096:
            # URL query strings can carry tokens (e.g. Pub/Sub push endpoints)
            return v.split("?", 1)[0] + "?" + REDACTED
        return v

    return walk(copy.deepcopy(data) if isinstance(data, (dict, list)) else data)


# ---------------------------------------------------------------------------
# Extraction framework
# ---------------------------------------------------------------------------


@dataclass
class GCPContext:
    """What an extractor knows about the asset being mapped."""

    name: str
    asset_type: str
    data: dict[str, Any]
    project_id: str | None = None
    project_number: str | None = None
    location: str | None = None
    ancestors: list[str] = field(default_factory=list)

    @property
    def region(self) -> str | None:
        loc = self.location or ""
        if re.fullmatch(r"[a-z]+-[a-z]+\d+-[a-z]", loc):
            return loc.rsplit("-", 1)[0]
        return loc or None

    def default_sa(self) -> str | None:
        if self.project_number:
            return f"{self.project_number}-compute@developer.gserviceaccount.com"
        return None


@dataclass
class Extracted:
    """Output of one extractor run."""

    relations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    exposure: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self,
        target: Any,
        edge: EdgeType,
        relationship: str | None = None,
        *,
        reverse: bool = False,
        description: str | None = None,
        **properties: Any,
    ) -> None:
        r = rel(target, edge, relationship, reverse=reverse, description=description, **properties)
        if r and r not in self.relations:
            self.relations.append(r)

    def sa(
        self, ref: Any, ctx: GCPContext, description: str | None = None, **props: Any
    ) -> str | None:
        """Declare that the asset runs as a service account."""
        if ref == "default":
            ref = ctx.default_sa()
        email = sa_email(ref)
        if not email:
            return None
        self.add(sa_ref(email), EdgeType.ASSUMES_ROLE, "RUNS_ON", description=description, **props)
        return email

    def alias(self, *values: Any) -> None:
        for v in values:
            if isinstance(v, str) and v and v not in self.aliases:
                self.aliases.append(v)

    def expose(
        self,
        reason: str,
        protocol: str | None = None,
        ports: Iterable[str] = (),
        kind: str = "INTERNET_EXPOSED",
    ) -> None:
        """Mark the asset reachable from the internet (0.0.0.0/0)."""
        entry = {"via": reason, "kind": kind}
        if protocol:
            entry["protocol"] = protocol
        port_list = [str(p) for p in ports if p not in (None, "")]
        if port_list:
            entry["ports"] = port_list
        if entry not in self.exposure:
            self.exposure.append(entry)


Extractor = Callable[[GCPContext, Extracted], None]
EXTRACTORS: dict[str, Extractor] = {}


def _extractor(*asset_types: str) -> Callable[[Extractor], Extractor]:
    def register(fn: Extractor) -> Extractor:
        for t in asset_types:
            EXTRACTORS[t] = fn
        return fn

    return register


def extract(ctx: GCPContext) -> Extracted:
    """Run the extractor for ``ctx.asset_type`` plus the generic CMEK scan."""
    out = Extracted()
    fn = EXTRACTORS.get(ctx.asset_type)
    if fn is not None:
        try:
            fn(ctx, out)
        except Exception as exc:  # one malformed resource must not stop the sweep
            logger.debug("GCP extractor failed for %s: %s", ctx.name, exc, exc_info=True)
            out.metadata["extraction_error"] = f"{type(exc).__name__}: {exc}"
    if ctx.asset_type.startswith("cloudkms.googleapis.com/"):
        return out
    keys = kms_refs(ctx.data)
    if keys:
        out.metadata["kms_keys"] = keys
        for key in keys:
            out.add(
                key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", description=f"encrypted with {key}"
            )
    return out


# ---------------------------------------------------------------------------
# Resource hierarchy
# ---------------------------------------------------------------------------


def _crm_parent(parent: Any) -> str | None:
    if isinstance(parent, dict):
        ptype, pid = parent.get("type"), _num(parent.get("id"))
        if ptype and pid:
            return f"//cloudresourcemanager.googleapis.com/{ptype.rstrip('s')}s/{pid}"
        return None
    if isinstance(parent, str) and re.fullmatch(r"(organizations|folders|projects)/[^/]+", parent):
        return f"//cloudresourcemanager.googleapis.com/{parent}"
    return None


def _ancestor_parent(ctx: GCPContext) -> str | None:
    return _crm_parent(ctx.ancestors[1]) if len(ctx.ancestors) > 1 else None


@_extractor("cloudresourcemanager.googleapis.com/Project")
def _project(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    number = _num(d.get("projectNumber"))
    if not number and isinstance(d.get("name"), str) and d["name"].startswith("projects/"):
        number = d["name"].split("/", 1)[1]
    number = number or ctx.project_number or relative_name(ctx.name).split("/")[-1]
    pid = d.get("projectId") or ctx.project_id
    out.alias(f"projects/{number}", number)
    if pid:
        out.alias(
            f"projects/{pid}",
            pid,
            f"//cloudresourcemanager.googleapis.com/projects/{pid}",
        )
        out.metadata["account_id"] = pid
        out.metadata["project_id"] = pid
    out.alias(f"//cloudresourcemanager.googleapis.com/projects/{number}")
    out.metadata["project_number"] = number
    out.metadata["display_name"] = d.get("displayName") or (
        d.get("name") if not str(d.get("name", "")).startswith("projects/") else None
    )
    out.metadata["lifecycle_state"] = d.get("lifecycleState") or d.get("state")
    parent = _crm_parent(d.get("parent")) or _ancestor_parent(ctx)
    out.add(parent, EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT", reverse=True)


@_extractor("cloudresourcemanager.googleapis.com/Folder")
def _folder(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    rel_name = (
        d.get("name") if str(d.get("name", "")).startswith("folders/") else relative_name(ctx.name)
    )
    out.alias(rel_name)
    out.metadata["display_name"] = d.get("displayName")
    out.metadata["lifecycle_state"] = d.get("lifecycleState") or d.get("state")
    parent = _crm_parent(d.get("parent")) or _ancestor_parent(ctx)
    out.add(parent, EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT", reverse=True)


@_extractor("cloudresourcemanager.googleapis.com/Organization")
def _organization(ctx: GCPContext, out: Extracted) -> None:
    out.alias(relative_name(ctx.name))
    out.metadata["display_name"] = ctx.data.get("displayName")
    out.metadata["directory_customer_id_present"] = bool(
        dig(ctx.data, "owner", "directoryCustomerId")
    )
    out.metadata["lifecycle_state"] = ctx.data.get("lifecycleState") or ctx.data.get("state")


@_extractor("orgpolicy.googleapis.com/Policy")
def _org_policy_v2(ctx: GCPContext, out: Extracted) -> None:
    rel_name = relative_name(ctx.name)
    attached = rel_name.split("/policies/", 1)[0]
    out.add(
        full_name(attached), EdgeType.GOVERNS, "SCP_RESTRICTS", description="organization policy"
    )
    spec = ctx.data.get("spec") or {}
    rules = []
    for r in _list(spec.get("rules")):
        if not isinstance(r, dict):
            continue
        rules.append(
            {
                k: v
                for k, v in {
                    "enforce": r.get("enforce"),
                    "allow_all": r.get("allowAll"),
                    "deny_all": r.get("denyAll"),
                    "allowed_values": dig(r, "values", "allowedValues"),
                    "denied_values": dig(r, "values", "deniedValues"),
                    "condition": dig(r, "condition", "title") or dig(r, "condition", "expression"),
                }.items()
                if v not in (None, [], "")
            }
        )
    out.metadata.update(
        constraint="constraints/" + rel_name.rsplit("/policies/", 1)[-1],
        attached_to=full_name(attached),
        rules=rules,
        inherit_from_parent=spec.get("inheritFromParent"),
        reset=spec.get("reset"),
        dry_run=bool(ctx.data.get("dryRunSpec")),
    )


def perimeter_metadata(p: dict[str, Any]) -> tuple[dict[str, Any], list[tuple[str, bool]]]:
    """Metadata and governed resources ``(ref, dry_run)`` of a VPC-SC perimeter.

    Accepts both the proto (snake_case) and JSON (camelCase) shapes.
    """

    def g(d: Any, snake: str, camel: str) -> Any:
        if not isinstance(d, dict):
            return None
        return d.get(snake, d.get(camel))

    status = g(p, "status", "status") or {}
    spec = g(p, "spec", "spec") or {}
    dry_run = bool(g(p, "use_explicit_dry_run_spec", "useExplicitDryRunSpec"))
    ptype = g(p, "perimeter_type", "perimeterType")
    if isinstance(ptype, (int, float)):
        ptype = {0: "PERIMETER_TYPE_REGULAR", 1: "PERIMETER_TYPE_BRIDGE"}.get(
            int(ptype), str(ptype)
        )
    vpc = g(status, "vpc_accessible_services", "vpcAccessibleServices") or {}
    md = {
        "title": g(p, "title", "title"),
        "perimeter_type": ptype or "PERIMETER_TYPE_REGULAR",
        "restricted_services": list(g(status, "restricted_services", "restrictedServices") or []),
        "access_levels": list(g(status, "access_levels", "accessLevels") or []),
        "vpc_accessible_services_restricted": bool(
            g(vpc, "enable_restriction", "enableRestriction")
        ),
        "vpc_allowed_services": list(g(vpc, "allowed_services", "allowedServices") or []),
        "ingress_policy_count": len(g(status, "ingress_policies", "ingressPolicies") or []),
        "egress_policy_count": len(g(status, "egress_policies", "egressPolicies") or []),
        "uses_dry_run_spec": dry_run,
        "dry_run_restricted_services": list(
            g(spec, "restricted_services", "restrictedServices") or []
        ),
    }
    governed = [(r, False) for r in g(status, "resources", "resources") or []]
    governed += [
        (r, True) for r in g(spec, "resources", "resources") or [] if (r, False) not in governed
    ]
    return md, governed


@_extractor("accesscontextmanager.googleapis.com/ServicePerimeter")
def _perimeter(ctx: GCPContext, out: Extracted) -> None:
    md, governed = perimeter_metadata(ctx.data)
    out.metadata.update(md)
    for ref, dry in governed:
        out.add(ref, EdgeType.GOVERNS, "COMPLIANCE_GOVERNS", dry_run=dry or None)


# ---------------------------------------------------------------------------
# Compute: instances, disks, templates, groups
# ---------------------------------------------------------------------------


def _short(value: Any) -> Any:
    return value.rsplit("/", 1)[-1] if isinstance(value, str) else value


@_extractor("compute.googleapis.com/Instance")
def _instance(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    emails = []
    for sa in _list(d.get("serviceAccounts")):
        if isinstance(sa, dict):
            email = out.sa(
                sa.get("email"), ctx, "instance service account", scopes=sa.get("scopes")
            )
            if email:
                emails.append(email)
    public_ips, private_ips, networks = [], [], []
    for nic in _list(d.get("networkInterfaces")):
        if not isinstance(nic, dict):
            continue
        net = full_name(nic.get("network"), "compute")
        sub = full_name(nic.get("subnetwork"), "compute")
        if net and net not in networks:
            networks.append(net)
        out.add(sub or net, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
        if nic.get("networkIP"):
            private_ips.append(nic["networkIP"])
        for ac in _list(nic.get("accessConfigs")) + _list(nic.get("ipv6AccessConfigs")):
            if isinstance(ac, dict):
                ip = ac.get("natIP") or ac.get("externalIpv6")
                if ip:
                    public_ips.append(ip)
    for disk in _list(d.get("disks")):
        if isinstance(disk, dict):
            out.add(
                full_name(disk.get("source"), "compute"),
                EdgeType.ATTACHED_TO,
                reverse=True,
                description="disk attached to instance",
                boot=disk.get("boot") or None,
            )
    md_items = dig(d, "metadata", "items", default=[])
    out.metadata.update(
        network_tags=list(dig(d, "tags", "items", default=[]) or []),
        service_account_emails=emails,
        networks=networks,
        public_ips=public_ips,
        private_ips=private_ips,
        machine_type=_short(d.get("machineType")),
        can_ip_forward=bool(d.get("canIpForward")),
        deletion_protection=bool(d.get("deletionProtection")),
        shielded_vm=dig(d, "shieldedInstanceConfig", default={}),
        confidential_compute=bool(
            dig(d, "confidentialInstanceConfig", "enableConfidentialCompute")
        ),
        metadata_keys=[i.get("key") for i in md_items if isinstance(i, dict)],
    )
    for ip in public_ips:
        out.alias(ip)


@_extractor("compute.googleapis.com/Disk", "compute.googleapis.com/RegionDisk")
def _disk(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for user in _list(d.get("users")):
        out.add(
            full_name(user, "compute"),
            EdgeType.ATTACHED_TO,
            description="disk attached to instance",
        )
    out.add(full_name(d.get("sourceImage"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("sourceSnapshot"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(size_gb=_num(d.get("sizeGb")), disk_type=_short(d.get("type")))


@_extractor("compute.googleapis.com/Snapshot")
def _snapshot(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("sourceDisk"), "compute"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
    )


@_extractor("compute.googleapis.com/Image")
def _image(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("sourceDisk"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("sourceImage"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["family"] = d.get("family")


@_extractor("compute.googleapis.com/MachineImage")
def _machine_image(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("sourceInstance"), "compute"),
        EdgeType.REFERENCES,
        "BACKUP_TO",
        reverse=True,
    )


@_extractor(
    "compute.googleapis.com/InstanceTemplate", "compute.googleapis.com/RegionInstanceTemplate"
)
def _instance_template(ctx: GCPContext, out: Extracted) -> None:
    props = ctx.data.get("properties") or {}
    for sa in _list(props.get("serviceAccounts")):
        if isinstance(sa, dict):
            out.sa(sa.get("email"), ctx, "template service account")
    for nic in _list(props.get("networkInterfaces")):
        if isinstance(nic, dict):
            out.add(
                full_name(nic.get("subnetwork") or nic.get("network"), "compute"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
            )
    for disk in _list(props.get("disks")):
        if isinstance(disk, dict):
            out.add(
                full_name(dig(disk, "initializeParams", "sourceImage"), "compute"),
                EdgeType.USES_IMAGE,
                "RUNS_ON",
            )
    out.metadata.update(
        network_tags=list(dig(props, "tags", "items", default=[]) or []),
        machine_type=props.get("machineType"),
    )


@_extractor(
    "compute.googleapis.com/InstanceGroupManager",
    "compute.googleapis.com/RegionInstanceGroupManager",
)
def _igm(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    templates = [d.get("instanceTemplate")] + [
        v.get("instanceTemplate") for v in _list(d.get("versions")) if isinstance(v, dict)
    ]
    for t in templates:
        out.add(
            full_name(t, "compute"),
            EdgeType.REFERENCES,
            "DEPENDS_ON",
            description="instance template",
        )
    out.add(full_name(d.get("instanceGroup"), "compute"), EdgeType.MANAGES, "SCALES_WITH")
    for pool in _list(d.get("targetPools")):
        out.add(
            full_name(pool, "compute"),
            EdgeType.LOAD_BALANCER_TARGET,
            "LB_TARGETS_INSTANCE",
            reverse=True,
        )
    for hc in _list(d.get("autoHealingPolicies")):
        if isinstance(hc, dict):
            out.add(full_name(hc.get("healthCheck"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        target_size=_num(d.get("targetSize")), base_instance_name=d.get("baseInstanceName")
    )


@_extractor("compute.googleapis.com/Autoscaler", "compute.googleapis.com/RegionAutoscaler")
def _autoscaler(ctx: GCPContext, out: Extracted) -> None:
    out.add(full_name(ctx.data.get("target"), "compute"), EdgeType.MANAGES, "SCALES_WITH")


@_extractor("compute.googleapis.com/InstanceGroup", "compute.googleapis.com/RegionInstanceGroup")
def _instance_group(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("subnetwork") or d.get("network"), "compute"),
        EdgeType.CONTAINS,
        "SUBNET_CONTAINS_INSTANCE",
        reverse=True,
    )
    out.metadata.update(size=_num(d.get("size")), named_ports=d.get("namedPorts") or [])


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------


@_extractor("compute.googleapis.com/Network")
def _network(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for peering in _list(d.get("peerings")):
        if isinstance(peering, dict):
            out.add(
                full_name(peering.get("network"), "compute"),
                EdgeType.PEERING,
                "VPC_PEERED",
                description=f"VPC peering {peering.get('name', '')}",
                state=peering.get("state"),
                export_custom_routes=peering.get("exportCustomRoutes"),
                import_custom_routes=peering.get("importCustomRoutes"),
            )
    out.metadata.update(
        auto_create_subnetworks=d.get("autoCreateSubnetworks"),
        routing_mode=dig(d, "routingConfig", "routingMode"),
        mtu=_num(d.get("mtu")),
    )


@_extractor("compute.googleapis.com/Subnetwork")
def _subnetwork(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("network"), "compute"),
        EdgeType.CONTAINS,
        "VPC_CONTAINS_SUBNET",
        reverse=True,
    )
    out.metadata.update(
        network=full_name(d.get("network"), "compute"),
        ip_cidr_range=d.get("ipCidrRange"),
        secondary_ranges=[
            r.get("ipCidrRange") for r in _list(d.get("secondaryIpRanges")) if isinstance(r, dict)
        ],
        private_ip_google_access=d.get("privateIpGoogleAccess"),
        flow_logs_enabled=bool(dig(d, "logConfig", "enable") or d.get("enableFlowLogs")),
        purpose=d.get("purpose"),
    )


def _fw_entries(entries: Any) -> list[dict[str, Any]]:
    out = []
    for e in _list(entries):
        if isinstance(e, dict):
            out.append(
                {
                    "protocol": e.get("IPProtocol") or e.get("ipProtocol") or "all",
                    "ports": list(e.get("ports") or []),
                }
            )
    return out


@_extractor("compute.googleapis.com/Firewall")
def _firewall(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    network = full_name(d.get("network"), "compute")
    out.add(network, EdgeType.ATTACHED_TO, description="firewall rule of network")
    direction = (d.get("direction") or "INGRESS").upper()
    allowed, denied = _fw_entries(d.get("allowed")), _fw_entries(d.get("denied"))
    action = "allow" if allowed or not denied else "deny"
    rule = {
        "direction": direction,
        "action": action,
        "priority": int(float(d.get("priority", 1000))),
        "disabled": bool(d.get("disabled")),
        "protocols": allowed or denied,
        "source_ranges": list(d.get("sourceRanges") or []),
        "destination_ranges": list(d.get("destinationRanges") or []),
        "source_tags": list(d.get("sourceTags") or []),
        "source_service_accounts": [s.lower() for s in d.get("sourceServiceAccounts") or []],
        "target_tags": list(d.get("targetTags") or []),
        "target_service_accounts": [s.lower() for s in d.get("targetServiceAccounts") or []],
    }
    internet = direction == "INGRESS" and any(r in INTERNET_CIDRS for r in rule["source_ranges"])
    out.metadata.update(
        network=network,
        direction=direction,
        action=action,
        priority=rule["priority"],
        disabled=rule["disabled"],
        target_tags=rule["target_tags"],
        target_service_accounts=rule["target_service_accounts"],
        source_ranges=rule["source_ranges"],
        ingress_rules=[rule] if direction == "INGRESS" else [],
        egress_rules=[rule] if direction == "EGRESS" else [],
        internet_source=internet,
        allows_internet_ingress=internet and action == "allow" and not rule["disabled"],
        logging_enabled=bool(dig(d, "logConfig", "enable")),
    )


@_extractor(
    "compute.googleapis.com/FirewallPolicy",
    "compute.googleapis.com/NetworkFirewallPolicy",
    "compute.googleapis.com/RegionNetworkFirewallPolicy",
)
def _firewall_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    rules = []
    for r in _list(d.get("rules")):
        if not isinstance(r, dict):
            continue
        match = r.get("match") or {}
        rules.append(
            {
                "direction": r.get("direction"),
                "action": r.get("action"),
                "priority": _num(r.get("priority")),
                "disabled": bool(r.get("disabled")),
                "source_ranges": list(match.get("srcIpRanges") or []),
                "destination_ranges": list(match.get("destIpRanges") or []),
                "protocols": [
                    {"protocol": c.get("ipProtocol"), "ports": c.get("ports") or []}
                    for c in _list(match.get("layer4Configs"))
                    if isinstance(c, dict)
                ],
            }
        )
    for assoc in _list(d.get("associations")):
        if isinstance(assoc, dict):
            target = assoc.get("attachmentTarget")
            out.add(
                full_name(target, "compute") or full_name(target),
                EdgeType.GOVERNS,
                "COMPLIANCE_GOVERNS",
            )
    out.metadata.update(
        ingress_rules=[r for r in rules if r.get("direction") == "INGRESS"],
        egress_rules=[r for r in rules if r.get("direction") == "EGRESS"],
        rule_count=len(rules),
    )


@_extractor("compute.googleapis.com/Route")
def _route(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("network"), "compute"), EdgeType.ATTACHED_TO, description="route of network"
    )
    hops = {
        "instance": d.get("nextHopInstance"),
        "vpn_tunnel": d.get("nextHopVpnTunnel"),
        "ilb": d.get("nextHopIlb") if "/" in str(d.get("nextHopIlb") or "") else None,
        "peering": None,
    }
    for kind, hop in hops.items():
        out.add(
            full_name(hop, "compute"),
            EdgeType.ROUTE,
            "TRANSIT_ROUTED",
            description=f"next hop {kind}",
            destination=d.get("destRange"),
        )
    gw = d.get("nextHopGateway") or ""
    out.metadata.update(
        dest_range=d.get("destRange"),
        priority=_num(d.get("priority")),
        to_internet=str(gw).endswith("default-internet-gateway"),
        next_hop_ip=d.get("nextHopIp"),
        next_hop_peering=d.get("nextHopPeering"),
        network_tags=list(d.get("tags") or []),
    )


@_extractor("compute.googleapis.com/Router")
def _router(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("network"), "compute"),
        EdgeType.ATTACHED_TO,
        description="Cloud Router of network",
    )
    nats = []
    for nat in _list(d.get("nats")):
        if not isinstance(nat, dict):
            continue
        nats.append(
            {
                "name": nat.get("name"),
                "source_ranges": nat.get("sourceSubnetworkIpRangesToNat"),
                "ip_allocation": nat.get("natIpAllocateOption"),
                "logging": bool(dig(nat, "logConfig", "enable")),
            }
        )
        for sn in _list(nat.get("subnetworks")):
            if isinstance(sn, dict):
                out.add(
                    full_name(sn.get("name"), "compute"),
                    EdgeType.ROUTE,
                    "NAT_TRANSLATED",
                    reverse=True,
                    description="egress via Cloud NAT",
                )
        for ip in _list(nat.get("natIps")):
            out.add(full_name(ip, "compute"), EdgeType.ATTACHED_TO, reverse=True)
    for iface in _list(d.get("interfaces")):
        if isinstance(iface, dict):
            out.add(
                full_name(iface.get("linkedVpnTunnel"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED"
            )
            out.add(
                full_name(iface.get("linkedInterconnectAttachment"), "compute"),
                EdgeType.ROUTE,
                "TRANSIT_ROUTED",
            )
    out.metadata.update(
        nat=nats,
        nat_enabled=bool(nats),
        bgp_asn=_num(dig(d, "bgp", "asn")),
        bgp_peer_count=len(_list(d.get("bgpPeers"))),
    )


@_extractor("compute.googleapis.com/VpnGateway", "compute.googleapis.com/TargetVpnGateway")
def _vpn_gateway(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("network"), "compute"), EdgeType.ATTACHED_TO)
    for t in _list(d.get("tunnels")):
        out.add(full_name(t, "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.metadata["interface_ips"] = [
        i.get("ipAddress") for i in _list(d.get("vpnInterfaces")) if isinstance(i, dict)
    ]


@_extractor("compute.googleapis.com/VpnTunnel")
def _vpn_tunnel(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("vpnGateway") or d.get("targetVpnGateway"), "compute"), EdgeType.ATTACHED_TO
    )
    out.add(full_name(d.get("peerExternalGateway"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.add(full_name(d.get("peerGcpGateway"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.add(full_name(d.get("router"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        peer_ip=d.get("peerIp"), ike_version=_num(d.get("ikeVersion")), status=d.get("status")
    )


@_extractor("compute.googleapis.com/InterconnectAttachment")
def _interconnect_attachment(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("router"), "compute"), EdgeType.ATTACHED_TO)
    out.add(full_name(d.get("interconnect"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    out.metadata.update(attachment_type=d.get("type"), encryption=d.get("encryption"))


@_extractor("compute.googleapis.com/ServiceAttachment")
def _service_attachment(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("targetService") or d.get("producerForwardingRule"), "compute"),
        EdgeType.ROUTE,
        "SERVES_TRAFFIC_TO",
    )
    for sn in _list(d.get("natSubnets")):
        out.add(full_name(sn, "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        connection_preference=d.get("connectionPreference"),
        consumer_accept_lists=[
            a.get("projectIdOrNum") or a.get("networkUrl")
            for a in _list(d.get("consumerAcceptLists"))
            if isinstance(a, dict)
        ],
        connected_endpoint_count=len(_list(d.get("connectedEndpoints"))),
    )


@_extractor("compute.googleapis.com/Address", "compute.googleapis.com/GlobalAddress")
def _address(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    external = (d.get("addressType") or "EXTERNAL") == "EXTERNAL"
    for user in _list(d.get("users")):
        out.add(full_name(user, "compute"), EdgeType.ATTACHED_TO, description="address in use")
    if not external:
        out.add(
            full_name(d.get("subnetwork") or d.get("network"), "compute"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    if external and d.get("address"):
        out.alias(d["address"])
        out.metadata["public_ip"] = d["address"]
    out.metadata.update(
        address=d.get("address"), address_type=d.get("addressType"), purpose=d.get("purpose")
    )


@_extractor("compute.googleapis.com/Project")
def _compute_project(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        shared_vpc_host=d.get("xpnProjectStatus") == "HOST",
        xpn_project_status=d.get("xpnProjectStatus"),
        default_service_account=d.get("defaultServiceAccount"),
        common_metadata_keys=[
            i.get("key")
            for i in dig(d, "commonInstanceMetadata", "items", default=[])
            if isinstance(i, dict)
        ],
    )
    if ctx.project_id:
        out.add(
            f"//cloudresourcemanager.googleapis.com/projects/{ctx.project_id}",
            EdgeType.REFERENCES,
            "DEPENDS_ON",
        )


# ---------------------------------------------------------------------------
# Load balancing
# ---------------------------------------------------------------------------

_EXTERNAL_SCHEMES = {"EXTERNAL", "EXTERNAL_MANAGED"}


@_extractor("compute.googleapis.com/ForwardingRule", "compute.googleapis.com/GlobalForwardingRule")
def _forwarding_rule(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("target"), "compute"),
        EdgeType.ROUTE,
        "SERVES_TRAFFIC_TO",
        description="forwarding rule target",
    )
    out.add(full_name(d.get("backendService"), "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    scheme = d.get("loadBalancingScheme") or ""
    ip = d.get("IPAddress") or d.get("ipAddress")
    ports = list(d.get("ports") or ([d["portRange"]] if d.get("portRange") else []))
    protocol = d.get("IPProtocol") or d.get("ipProtocol")
    if isinstance(ip, str) and "/" in ip:
        out.add(full_name(ip, "compute"), EdgeType.ATTACHED_TO, reverse=True)
    elif ip and scheme in _EXTERNAL_SCHEMES:
        out.add(ip, EdgeType.ATTACHED_TO, reverse=True, description="static external address")
        out.alias(ip)
    if scheme not in _EXTERNAL_SCHEMES:
        out.add(
            full_name(d.get("subnetwork") or d.get("network"), "compute"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    psc = bool(d.get("pscConnectionId")) or "serviceAttachments" in str(d.get("target") or "")
    if scheme in _EXTERNAL_SCHEMES and not psc:
        out.expose(f"external load balancer ({scheme})", protocol=protocol, ports=ports)
    out.metadata.update(
        ip_address=ip,
        load_balancing_scheme=scheme,
        ip_protocol=protocol,
        ports=ports,
        network_tier=d.get("networkTier"),
        psc=psc,
    )


@_extractor(
    "compute.googleapis.com/TargetHttpProxy",
    "compute.googleapis.com/TargetHttpsProxy",
    "compute.googleapis.com/RegionTargetHttpProxy",
    "compute.googleapis.com/RegionTargetHttpsProxy",
    "compute.googleapis.com/TargetGrpcProxy",
    "compute.googleapis.com/TargetSslProxy",
    "compute.googleapis.com/TargetTcpProxy",
    "compute.googleapis.com/RegionTargetTcpProxy",
)
def _target_proxy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("urlMap"), "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    out.add(full_name(d.get("service"), "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    for cert in _list(d.get("sslCertificates")):
        out.add(
            full_name(cert, "compute") or full_name(cert, "certificatemanager"),
            EdgeType.REFERENCES,
            "CERTIFICATE_SECURES",
            reverse=True,
        )
    out.add(
        full_name(d.get("certificateMap"), "certificatemanager"),
        EdgeType.REFERENCES,
        "CERTIFICATE_SECURES",
        reverse=True,
    )
    out.add(full_name(d.get("sslPolicy"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata["quic_override"] = d.get("quicOverride")


@_extractor("compute.googleapis.com/UrlMap", "compute.googleapis.com/RegionUrlMap")
def _url_map(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    services = [d.get("defaultService")]
    services += [
        w.get("backendService")
        for w in _list(dig(d, "defaultRouteAction", "weightedBackendServices"))
        if isinstance(w, dict)
    ]
    for pm in _list(d.get("pathMatchers")):
        if not isinstance(pm, dict):
            continue
        services.append(pm.get("defaultService"))
        for pr in _list(pm.get("pathRules")):
            if isinstance(pr, dict):
                services.append(pr.get("service"))
        for rr in _list(pm.get("routeRules")):
            if isinstance(rr, dict):
                services.append(rr.get("service"))
                services += [
                    w.get("backendService")
                    for w in _list(dig(rr, "routeAction", "weightedBackendServices"))
                    if isinstance(w, dict)
                ]
    for svc in services:
        out.add(full_name(svc, "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    out.metadata["hosts"] = sorted(
        {
            h
            for hr in _list(d.get("hostRules"))
            if isinstance(hr, dict)
            for h in hr.get("hosts") or []
        }
    )[:50]


@_extractor("compute.googleapis.com/BackendService", "compute.googleapis.com/RegionBackendService")
def _backend_service(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for b in _list(d.get("backends")):
        if isinstance(b, dict):
            out.add(
                full_name(b.get("group"), "compute"),
                EdgeType.LOAD_BALANCER_TARGET,
                "LB_TARGETS_INSTANCE",
                balancing_mode=b.get("balancingMode"),
            )
    for hc in _list(d.get("healthChecks")):
        out.add(full_name(hc, "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    for key in ("securityPolicy", "edgeSecurityPolicy"):
        out.add(
            full_name(d.get(key), "compute"),
            EdgeType.PROTECTS,
            "PROTECTED_BY_WAF",
            reverse=True,
            description="Cloud Armor policy",
        )
    out.add(full_name(d.get("network"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.metadata.update(
        load_balancing_scheme=d.get("loadBalancingScheme"),
        protocol=d.get("protocol"),
        iap_enabled=bool(dig(d, "iap", "enabled")),
        cdn_enabled=bool(d.get("enableCDN")),
        logging_enabled=bool(dig(d, "logConfig", "enable")),
        security_policy=full_name(d.get("securityPolicy"), "compute"),
    )


@_extractor("compute.googleapis.com/BackendBucket")
def _backend_bucket(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    if d.get("bucketName"):
        out.add(
            f"//storage.googleapis.com/{d['bucketName']}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    out.add(
        full_name(d.get("edgeSecurityPolicy"), "compute"),
        EdgeType.PROTECTS,
        "PROTECTED_BY_WAF",
        reverse=True,
    )
    out.metadata["cdn_enabled"] = bool(d.get("enableCdn"))


@_extractor("compute.googleapis.com/TargetPool")
def _target_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for inst in _list(d.get("instances")):
        out.add(full_name(inst, "compute"), EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE")
    for hc in _list(d.get("healthChecks")):
        out.add(full_name(hc, "compute"), EdgeType.REFERENCES, "DEPENDS_ON")
    out.add(full_name(d.get("backupPool"), "compute"), EdgeType.REFERENCES, "DEPENDS_ON")


@_extractor("compute.googleapis.com/TargetInstance")
def _target_instance(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        full_name(ctx.data.get("instance"), "compute"),
        EdgeType.LOAD_BALANCER_TARGET,
        "LB_TARGETS_INSTANCE",
    )


@_extractor(
    "compute.googleapis.com/NetworkEndpointGroup",
    "compute.googleapis.com/GlobalNetworkEndpointGroup",
    "compute.googleapis.com/RegionNetworkEndpointGroup",
)
def _neg(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid, region = ctx.project_id, ctx.region
    run_svc = dig(d, "cloudRun", "service")
    if run_svc and pid and region:
        out.add(
            f"//run.googleapis.com/projects/{pid}/locations/{region}/services/{run_svc}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    fn = dig(d, "cloudFunction", "function")
    if fn and pid and region:
        out.add(
            f"//cloudfunctions.googleapis.com/projects/{pid}/locations/{region}/functions/{fn}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    ae = dig(d, "appEngine", "service")
    if ae and pid:
        out.add(
            f"//appengine.googleapis.com/apps/{pid}/services/{ae}",
            EdgeType.LOAD_BALANCER_TARGET,
            "SERVES_TRAFFIC_TO",
        )
    psc = d.get("pscTargetService")
    if isinstance(psc, str) and "/" in psc:
        out.add(full_name(psc, "compute"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO")
    out.add(
        full_name(d.get("subnetwork") or d.get("network"), "compute"),
        EdgeType.CONTAINS,
        "SUBNET_CONTAINS_INSTANCE",
        reverse=True,
    )
    out.metadata["network_endpoint_type"] = d.get("networkEndpointType")


@_extractor("compute.googleapis.com/SecurityPolicy", "compute.googleapis.com/RegionSecurityPolicy")
def _security_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        policy_type=d.get("type"),
        rule_count=len(_list(d.get("rules"))),
        adaptive_protection=bool(
            dig(d, "adaptiveProtectionConfig", "layer7DdosDefenseConfig", "enable")
        ),
    )


@_extractor("compute.googleapis.com/SslCertificate", "compute.googleapis.com/RegionSslCertificate")
def _ssl_cert(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        certificate_type=d.get("type"),
        domains=list(
            dig(d, "managed", "domains", default=[]) or d.get("subjectAlternativeNames") or []
        ),
        expire_time=d.get("expireTime"),
    )


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
    out.add(sub or net, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
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


@_extractor("run.googleapis.com/Service", "run.googleapis.com/Job")
def _cloud_run(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid, loc = ctx.project_id, ctx.location
    if isinstance(d.get("template"), dict) and not isinstance(d.get("spec"), dict):
        _cloud_run_v2(ctx, out)
        return
    meta = d.get("metadata") or {}
    tmpl = dig(d, "spec", "template", default={}) or {}
    if ctx.asset_type == "run.googleapis.com/Job":
        tmpl = dig(tmpl, "spec", "template", default={}) or tmpl
    ann = {
        **(meta.get("annotations") or {}),
        **(dig(tmpl, "metadata", "annotations", default={}) or {}),
    }
    spec = tmpl.get("spec") or {}
    out.sa(
        spec.get("serviceAccountName")
        or ("default" if ctx.asset_type == "run.googleapis.com/Service" else None),
        ctx,
        "Cloud Run service identity",
    )
    secret_alias: dict[str, str] = {}
    for item in str(ann.get("run.googleapis.com/secrets", "")).split(","):
        if ":" in item:
            alias, ref = item.split(":", 1)
            secret_alias[alias.strip()] = ref.strip()
    images = []
    for c in _list(spec.get("containers")):
        if not isinstance(c, dict):
            continue
        if c.get("image"):
            images.append(c["image"])
            out.add(image_repository(c["image"]), EdgeType.USES_IMAGE, "RUNS_ON")
        for env in _list(c.get("env")):
            ref = dig(env, "valueFrom", "secretKeyRef", "name") if isinstance(env, dict) else None
            if ref:
                out.add(
                    _secret_target(secret_alias.get(ref, ref), pid),
                    EdgeType.REFERENCES,
                    "READS_FROM",
                )
    for vol in _list(spec.get("volumes")):
        ref = dig(vol, "secret", "secretName") if isinstance(vol, dict) else None
        if ref:
            out.add(
                _secret_target(secret_alias.get(ref, ref), pid), EdgeType.REFERENCES, "READS_FROM"
            )
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
                out.add(
                    subnet_ref(ni.get("subnetwork"), pid, loc)
                    or network_ref(ni.get("network"), pid),
                    EdgeType.ROUTE,
                    "TRANSIT_ROUTED",
                    description="direct VPC egress",
                )
        except (ValueError, AttributeError, TypeError):
            pass
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
    out.sa(
        tmpl.get("serviceAccount")
        or ("default" if ctx.asset_type == "run.googleapis.com/Service" else None),
        ctx,
        "Cloud Run service identity",
    )
    images = []
    for c in _list(tmpl.get("containers")):
        if not isinstance(c, dict):
            continue
        if c.get("image"):
            images.append(c["image"])
            out.add(image_repository(c["image"]), EdgeType.USES_IMAGE, "RUNS_ON")
        for env in _list(c.get("env")):
            ref = (
                dig(env, "valueSource", "secretKeyRef", "secret") if isinstance(env, dict) else None
            )
            out.add(_secret_target(ref, pid), EdgeType.REFERENCES, "READS_FROM")
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
            out.add(
                subnet_ref(ni.get("subnetwork"), pid, loc) or network_ref(ni.get("network"), pid),
                EdgeType.ROUTE,
                "TRANSIT_ROUTED",
            )
    ingress = d.get("ingress") or "INGRESS_TRAFFIC_ALL"
    if ctx.asset_type == "run.googleapis.com/Service" and ingress == "INGRESS_TRAFFIC_ALL":
        out.expose("Cloud Run ingress 'all'", protocol="tcp", ports=["443"])
    for url in [d.get("uri")] + list(d.get("urls") or []):
        out.alias(url, url_alias(url))
    out.metadata.update(ingress=ingress, url=url_alias(d.get("uri")), images=images)


@_extractor("cloudfunctions.googleapis.com/Function")
def _function_v2(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid, loc = ctx.project_id, ctx.location
    sc = d.get("serviceConfig") or {}
    out.sa(sc.get("serviceAccountEmail") or "default", ctx, "function runtime identity")
    out.add(
        full_name(sc.get("service"), "run"),
        EdgeType.MANAGES,
        "OWNED_BY",
        description="function runs on Cloud Run service",
    )
    out.add(_connector_target(sc.get("vpcConnector"), pid, loc), EdgeType.ROUTE, "TRANSIT_ROUTED")
    for s in _list(sc.get("secretEnvironmentVariables")) + _list(sc.get("secretVolumes")):
        if isinstance(s, dict):
            out.add(
                _secret_target(s.get("secret"), s.get("projectId") or pid),
                EdgeType.REFERENCES,
                "READS_FROM",
            )
    et = d.get("eventTrigger") or {}
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
    pid, loc = ctx.project_id, ctx.location
    out.sa(
        d.get("serviceAccountEmail") or (f"{pid}@appspot.gserviceaccount.com" if pid else None),
        ctx,
        "function runtime identity",
    )
    out.add(_connector_target(d.get("vpcConnector"), pid, loc), EdgeType.ROUTE, "TRANSIT_ROUTED")
    for s in _list(d.get("secretEnvironmentVariables")) + _list(d.get("secretVolumes")):
        if isinstance(s, dict):
            out.add(
                _secret_target(s.get("secret"), s.get("projectId") or pid),
                EdgeType.REFERENCES,
                "READS_FROM",
            )
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


# ---------------------------------------------------------------------------
# Messaging and events
# ---------------------------------------------------------------------------


def _bq_dataset_from_table(table: Any) -> str | None:
    if not isinstance(table, str) or not table:
        return None
    m = re.match(r"^([^:.]+)[:.]([^.]+)\.", table)
    if m:
        return f"//bigquery.googleapis.com/projects/{m.group(1)}/datasets/{m.group(2)}"
    return None


@_extractor("pubsub.googleapis.com/Topic")
def _topic(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(dig(d, "schemaSettings", "schema"), "pubsub"), EdgeType.REFERENCES, "DEPENDS_ON"
    )
    out.metadata["message_retention"] = d.get("messageRetentionDuration")


@_extractor("pubsub.googleapis.com/Subscription")
def _subscription(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("topic"), "pubsub"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        reverse=True,
        description="topic delivers to subscription",
    )
    push = d.get("pushConfig") or {}
    endpoint = url_alias(push.get("pushEndpoint"))
    if endpoint:
        out.add(endpoint, EdgeType.INVOKES, "INVOKES", description="push delivery")
    out.sa(dig(push, "oidcToken", "serviceAccountEmail"), ctx, "push authentication identity")
    out.add(
        full_name(dig(d, "deadLetterPolicy", "deadLetterTopic"), "pubsub"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="dead-letter topic",
    )
    out.add(
        _bq_dataset_from_table(dig(d, "bigqueryConfig", "table")),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="BigQuery subscription",
    )
    bucket = dig(d, "cloudStorageConfig", "bucket")
    if bucket:
        out.add(
            f"//storage.googleapis.com/{bucket}",
            EdgeType.INVOKES,
            "STREAMS_TO",
            description="Cloud Storage subscription",
        )
    out.sa(
        dig(d, "bigqueryConfig", "serviceAccountEmail")
        or dig(d, "cloudStorageConfig", "serviceAccountEmail"),
        ctx,
        "export identity",
    )
    out.metadata.update(
        delivery="push"
        if endpoint
        else "bigquery"
        if d.get("bigqueryConfig")
        else "cloud_storage"
        if bucket
        else "pull",
        push_endpoint_host=endpoint,
        filter=d.get("filter"),
    )


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


@_extractor("logging.googleapis.com/LogSink")
def _log_sink(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    dest = full_name(d.get("destination"))
    out.add(dest, EdgeType.LOGS_TO, "LOGS_TO", description="log sink destination")
    flt = d.get("filter")
    out.metadata.update(
        destination=dest,
        filter=flt[:500] if isinstance(flt, str) else flt,
        include_children=bool(d.get("includeChildren")),
        disabled=bool(d.get("disabled")),
        writer_identity=d.get("writerIdentity"),
        exclusion_count=len(_list(d.get("exclusions"))),
    )


@_extractor("logging.googleapis.com/LogBucket")
def _log_bucket(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        retention_days=_num(d.get("retentionDays")),
        locked=bool(d.get("locked")),
        analytics_enabled=bool(d.get("analyticsEnabled")),
    )


# ---------------------------------------------------------------------------
# Data stores
# ---------------------------------------------------------------------------


@_extractor("sqladmin.googleapis.com/Instance")
def _cloud_sql(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    ipc = dig(d, "settings", "ipConfiguration", default={}) or {}
    out.add(
        full_name(ipc.get("privateNetwork"), "compute"),
        EdgeType.ATTACHED_TO,
        description="private services access network",
    )
    nets = [n.get("value") for n in _list(ipc.get("authorizedNetworks")) if isinstance(n, dict)]
    ipv4 = ipc.get("ipv4Enabled", True)
    public_ips = [
        i.get("ipAddress")
        for i in _list(d.get("ipAddresses"))
        if isinstance(i, dict) and i.get("type") == "PRIMARY"
    ]
    if ipv4 and any(n in INTERNET_CIDRS for n in nets):
        out.expose(
            "Cloud SQL authorized network 0.0.0.0/0",
            protocol="tcp",
            ports=[_SQL_PORTS.get(str(d.get("databaseVersion", "")).split("_")[0], "")],
        )
    master = d.get("masterInstanceName")
    if isinstance(master, str) and master:
        pid = master.split(":", 1)[0] if ":" in master else ctx.project_id
        out.add(
            f"//cloudsql.googleapis.com/projects/{pid}/instances/{master.rsplit(':', 1)[-1]}",
            EdgeType.REFERENCES,
            "REPLICATES_TO",
            reverse=True,
        )
    for ip in public_ips:
        out.alias(ip)
    out.metadata.update(
        database_version=d.get("databaseVersion"),
        tier=dig(d, "settings", "tier"),
        public_ip_enabled=bool(ipv4),
        public_ips=public_ips,
        authorized_networks=nets,
        ssl_mode=ipc.get("sslMode") or ("ENCRYPTED_ONLY" if ipc.get("requireSsl") else None),
        backups_enabled=bool(dig(d, "settings", "backupConfiguration", "enabled")),
        availability_type=dig(d, "settings", "availabilityType"),
    )


_SQL_PORTS = {"POSTGRES": "5432", "MYSQL": "3306", "SQLSERVER": "1433"}


@_extractor("redis.googleapis.com/Instance", "memcache.googleapis.com/Instance")
def _redis(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(network_ref(d.get("authorizedNetwork"), ctx.project_id), EdgeType.ATTACHED_TO)
    out.metadata.update(
        connect_mode=d.get("connectMode"),
        auth_enabled=d.get("authEnabled"),
        transit_encryption=d.get("transitEncryptionMode"),
    )


@_extractor("redis.googleapis.com/Cluster")
def _redis_cluster(ctx: GCPContext, out: Extracted) -> None:
    for psc in _list(ctx.data.get("pscConfigs")):
        if isinstance(psc, dict):
            out.add(network_ref(psc.get("network"), ctx.project_id), EdgeType.ATTACHED_TO)


@_extractor("file.googleapis.com/Instance")
def _filestore(ctx: GCPContext, out: Extracted) -> None:
    for net in _list(ctx.data.get("networks")):
        if isinstance(net, dict):
            out.add(
                network_ref(net.get("network"), ctx.project_id),
                EdgeType.ATTACHED_TO,
                connect_mode=net.get("connectMode"),
            )


@_extractor("alloydb.googleapis.com/Cluster")
def _alloydb_cluster(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        network_ref(dig(d, "networkConfig", "network") or d.get("network"), ctx.project_id),
        EdgeType.ATTACHED_TO,
    )


@_extractor("alloydb.googleapis.com/Instance")
def _alloydb_instance(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        ctx.name.split("/instances/", 1)[0],
        EdgeType.CONTAINS,
        "CLUSTER_CONTAINS_SERVICE",
        reverse=True,
    )
    nc = d.get("networkConfig") or {}
    nets = [
        n.get("cidrRange")
        for n in _list(nc.get("authorizedExternalNetworks"))
        if isinstance(n, dict)
    ]
    if nc.get("enablePublicIp") and (not nets or any(n in INTERNET_CIDRS for n in nets)):
        out.expose("AlloyDB public IP", protocol="tcp", ports=["5432"])
    out.metadata.update(public_ip_enabled=bool(nc.get("enablePublicIp")), authorized_networks=nets)


@_extractor("bigquery.googleapis.com/Dataset")
def _bq_dataset(ctx: GCPContext, out: Extracted) -> None:
    public = []
    for entry in _list(ctx.data.get("access")):
        if not isinstance(entry, dict):
            continue
        member = entry.get("iamMember") or entry.get("specialGroup")
        if member in PUBLIC_MEMBERS:
            public.append({"member": member, "role": entry.get("role")})
        view = entry.get("view") or (entry.get("dataset") or {}).get("dataset")
        if isinstance(view, dict) and view.get("projectId") and view.get("datasetId"):
            out.add(
                f"//bigquery.googleapis.com/projects/{view['projectId']}/datasets/{view['datasetId']}",
                EdgeType.GRANTS_ACCESS,
                "READS_FROM",
                reverse=True,
                description="authorized view/dataset",
            )
    if public:
        out.expose(
            "BigQuery dataset access granted to " + ", ".join(sorted({p["member"] for p in public}))
        )
        out.metadata["public_access"] = public
    out.metadata["access_entry_count"] = len(_list(ctx.data.get("access")))


@_extractor("storage.googleapis.com/Bucket")
def _bucket(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    iam_cfg = d.get("iamConfiguration") or {}
    log_bucket = dig(d, "logging", "logBucket")
    if log_bucket:
        out.add(
            f"//storage.googleapis.com/{log_bucket}",
            EdgeType.LOGS_TO,
            "LOGS_TO",
            description="access logs",
        )
    public_acl = sorted(
        {
            a.get("entity")
            for a in _list(d.get("acl")) + _list(d.get("defaultObjectAcl"))
            if isinstance(a, dict) and a.get("entity") in PUBLIC_MEMBERS
        }
    )
    if public_acl:
        out.expose("bucket ACL grants " + ", ".join(public_acl))
    out.metadata.update(
        uniform_bucket_level_access=bool(
            dig(iam_cfg, "uniformBucketLevelAccess", "enabled")
            or dig(iam_cfg, "bucketPolicyOnly", "enabled")
        ),
        public_access_prevention=iam_cfg.get("publicAccessPrevention"),
        versioning=bool(dig(d, "versioning", "enabled")),
        retention_locked=bool(dig(d, "retentionPolicy", "isLocked")),
        website=bool(d.get("website")),
        storage_class=d.get("storageClass"),
        location_type=d.get("locationType"),
        public_acl=public_acl,
    )


@_extractor("cloudkms.googleapis.com/CryptoKey")
def _crypto_key(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        ctx.name.split("/cryptoKeys/", 1)[0],
        EdgeType.CONTAINS,
        reverse=True,
        description="key ring contains key",
    )
    out.metadata.update(
        purpose=d.get("purpose"),
        rotation_period=d.get("rotationPeriod"),
        protection_level=dig(d, "versionTemplate", "protectionLevel"),
        primary_state=dig(d, "primary", "state"),
    )


@_extractor("secretmanager.googleapis.com/Secret")
def _secret(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for t in _list(d.get("topics")):
        if isinstance(t, dict):
            out.add(
                full_name(t.get("name"), "pubsub"),
                EdgeType.INVOKES,
                "INVOKES",
                description="secret event notifications",
            )
    out.metadata.update(
        rotation=bool(d.get("rotation")),
        replication="user_managed" if dig(d, "replication", "userManaged") else "automatic",
    )


@_extractor("artifactregistry.googleapis.com/Repository")
def _ar_repo(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.metadata.update(
        format=d.get("format"),
        mode=d.get("mode"),
        immutable_tags=bool(dig(d, "dockerConfig", "immutableTags")),
    )


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
# DNS, connectivity
# ---------------------------------------------------------------------------


@_extractor("dns.googleapis.com/ManagedZone")
def _dns_zone(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for n in _list(dig(d, "privateVisibilityConfig", "networks")):
        if isinstance(n, dict):
            out.add(full_name(n.get("networkUrl"), "compute"), EdgeType.ATTACHED_TO, "DNS_RESOLVED")
    for c in _list(dig(d, "privateVisibilityConfig", "gkeClusters")):
        if isinstance(c, dict):
            out.add(
                full_name(c.get("gkeClusterName"), "container"),
                EdgeType.ATTACHED_TO,
                "DNS_RESOLVED",
            )
    out.add(
        full_name(dig(d, "peeringConfig", "targetNetwork", "networkUrl"), "compute"),
        EdgeType.ROUTE,
        "DNS_RESOLVED",
    )
    out.metadata.update(
        dns_name=d.get("dnsName"),
        visibility=d.get("visibility") or "public",
        dnssec=dig(d, "dnssecConfig", "state"),
        forwarding_targets=[
            t.get("ipv4Address")
            for t in _list(dig(d, "forwardingConfig", "targetNameServers"))
            if isinstance(t, dict)
        ],
    )


@_extractor("dns.googleapis.com/Policy", "dns.googleapis.com/ResponsePolicy")
def _dns_policy(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for n in _list(d.get("networks")):
        if isinstance(n, dict):
            out.add(full_name(n.get("networkUrl"), "compute"), EdgeType.ATTACHED_TO, "DNS_RESOLVED")
    for c in _list(d.get("gkeClusters")):
        if isinstance(c, dict):
            out.add(
                full_name(c.get("gkeClusterName"), "container"),
                EdgeType.ATTACHED_TO,
                "DNS_RESOLVED",
            )
    out.metadata["inbound_forwarding"] = d.get("enableInboundForwarding")


@_extractor("vpcaccess.googleapis.com/Connector")
def _vpc_connector(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    pid = ctx.project_id
    out.add(network_ref(d.get("network"), pid), EdgeType.ATTACHED_TO)
    sub = d.get("subnet") or {}
    if sub.get("name"):
        out.add(
            subnet_ref(sub["name"], sub.get("projectId") or pid, ctx.region),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
    out.metadata.update(
        ip_cidr_range=d.get("ipCidrRange"), network=network_ref(d.get("network"), pid)
    )


@_extractor("networkconnectivity.googleapis.com/Spoke")
def _ncc_spoke(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("hub"), "networkconnectivity"), EdgeType.ATTACHED_TO)
    out.add(
        full_name(dig(d, "linkedVpcNetwork", "uri"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED"
    )
    for key in ("linkedVpnTunnels", "linkedInterconnectAttachments"):
        for uri in _list(dig(d, key, "uris")):
            out.add(full_name(uri, "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED")
    for inst in _list(dig(d, "linkedRouterApplianceInstances", "instances")):
        if isinstance(inst, dict):
            out.add(
                full_name(inst.get("virtualMachine"), "compute"), EdgeType.ROUTE, "TRANSIT_ROUTED"
            )


@_extractor("managedkafka.googleapis.com/Cluster")
def _kafka(ctx: GCPContext, out: Extracted) -> None:
    for nc in _list(dig(ctx.data, "gcpConfig", "accessConfig", "networkConfigs")):
        if isinstance(nc, dict):
            out.add(
                full_name(nc.get("subnet"), "compute"),
                EdgeType.CONTAINS,
                "SUBNET_CONTAINS_INSTANCE",
                reverse=True,
            )


# ---------------------------------------------------------------------------
# Data processing, ML, CI/CD
# ---------------------------------------------------------------------------


@_extractor("composer.googleapis.com/Environment")
def _composer(ctx: GCPContext, out: Extracted) -> None:
    cfg = ctx.data.get("config") or {}
    nc = cfg.get("nodeConfig") or {}
    out.sa(nc.get("serviceAccount") or "default", ctx, "Composer worker identity")
    out.add(
        full_name(nc.get("subnetwork"), "compute") or full_name(nc.get("network"), "compute"),
        EdgeType.CONTAINS,
        "SUBNET_CONTAINS_INSTANCE",
        reverse=True,
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
    out.add(
        full_name(gce.get("subnetworkUri"), "compute")
        or network_ref(gce.get("networkUri"), ctx.project_id),
        EdgeType.CONTAINS,
        "SUBNET_CONTAINS_INSTANCE",
        reverse=True,
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
            out.add(
                subnet_ref(wp.get("subnetwork"), ctx.project_id, ctx.region)
                or network_ref(wp.get("network"), ctx.project_id),
                EdgeType.CONTAINS,
                "SUBNET_CONTAINS_INSTANCE",
                reverse=True,
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
        out.add(
            full_name(sub, "compute") or full_name(net, "compute"),
            EdgeType.CONTAINS,
            "SUBNET_CONTAINS_INSTANCE",
            reverse=True,
        )
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


def _append_relation(asset: CloudAsset, relation: dict[str, Any] | None) -> None:
    if not relation:
        return
    rels = asset.metadata.setdefault("relations", [])
    if relation not in rels:
        rels.append(relation)


def mark_exposed(asset: CloudAsset, reason: str, **detail: Any) -> None:
    """Flag an asset internet-exposed and record why (drives 0.0.0.0/0 edges)."""
    asset.is_internet_exposed = True
    reasons = asset.metadata.setdefault("exposure_reasons", [])
    if reason not in reasons:
        reasons.append(reason)
    entry = {
        "via": reason,
        "kind": detail.pop("kind", None) or "INTERNET_EXPOSED",
        **{k: v for k, v in detail.items() if v},
    }
    ingress = asset.metadata.setdefault("internet_ingress", [])
    if entry not in ingress:
        ingress.append(entry)


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
    idx = _index(assets)
    created: list[CloudAsset] = []
    grants: dict[tuple[str, str, str], dict[str, Any]] = {}
    principals: dict[str, CloudAsset] = {}

    def principal_for(member: str) -> CloudAsset | None:
        ident = principal_identifier(member)
        found = idx.get(ident) or idx.get(ident.lower())
        if found is None and ident.startswith("serviceAccount:"):
            found = idx.get(f"{PRINCIPAL_PREFIX}{ident}")
        if found is not None:
            return found
        asset = principal_asset(member)
        if asset is None:
            return None
        created.append(asset)
        for a in [asset.arn, *asset.metadata.get("aliases", [])]:
            idx.setdefault(a, asset)
            idx.setdefault(a.lower(), asset)
        return asset

    for pol in policies:
        resource = pol.get("resource")
        if not isinstance(resource, str) or not resource:
            continue
        target = idx.get(resource)
        is_sa_resource = (
            "/serviceAccounts/" in resource
            and resource.startswith("//iam.googleapis.com/")
            and "/keys/" not in resource
        )
        for binding in (pol.get("policy") or {}).get("bindings") or []:
            role = binding.get("role") or ""
            cond = (binding.get("condition") or {}).get("title")
            for member in binding.get("members") or []:
                if not isinstance(member, str):
                    continue
                if member in PUBLIC_MEMBERS:
                    if target is not None:
                        mark_exposed(target, f"IAM {role} granted to {member}")
                        public = target.metadata.setdefault("public_access", [])
                        if {"member": member, "role": role} not in public:
                            public.append({"member": member, "role": role})
                    continue
                principal = principal_for(member)
                if principal is None or principal is target:
                    continue
                principals[principal.id] = principal
                edge = (
                    EdgeType.ASSUMES_ROLE
                    if is_sa_resource and role in IMPERSONATION_ROLES
                    else EdgeType.GRANTS_ACCESS
                )
                info = grants.setdefault(
                    (principal.id, resource, edge.value), {"roles": [], "conditions": []}
                )
                if role not in info["roles"]:
                    info["roles"].append(role)
                if cond and cond not in info["conditions"]:
                    info["conditions"].append(cond)

    for (pid, resource, edge_value), info in grants.items():
        principal = principals[pid]
        edge = EdgeType(edge_value)
        relationship = (
            "ROLE_ASSUMES_ROLE" if edge == EdgeType.ASSUMES_ROLE else "POLICY_ALLOWS_ACTION"
        )
        desc = (
            f"{principal.name} can act as this service account"
            if edge == EdgeType.ASSUMES_ROLE
            else f"{principal.name} has {', '.join(info['roles'])}"
        )
        _append_relation(
            principal,
            rel(
                resource,
                edge,
                relationship,
                description=desc,
                role=info["roles"][0],
                roles=info["roles"],
                condition=", ".join(info["conditions"]) or None,
            ),
        )
    return created


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
            for ident in [placeholder.arn, *placeholder.metadata.get("aliases", [])]:
                idx.setdefault(ident, placeholder)
                idx.setdefault(ident.lower(), placeholder)
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
