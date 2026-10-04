"""Reference normalisation, small JSON helpers and sensitive-value scrubbing."""

from __future__ import annotations

import copy
import re
from typing import Any
from urllib.parse import urlparse

from cloudg.inventory._util import walk_strings

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
    for text in walk_strings(value):
        if len(found) >= limit:
            break
        if "/cryptoKeys/" not in text:
            continue
        for m in _CRYPTO_KEY_RE.findall(text):
            ref = f"//cloudkms.googleapis.com/{m}"
            if ref not in found:
                found.append(ref)
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
    """``value`` as a list: None is empty, a scalar is wrapped."""
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _short(value: Any) -> Any:
    return value.rsplit("/", 1)[-1] if isinstance(value, str) else value


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
