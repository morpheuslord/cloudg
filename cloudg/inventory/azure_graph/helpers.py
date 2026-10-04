"""Identifier and value helpers for the Azure Resource Graph inventory.

Identifier conventions:

- Entra principals (users, groups, service principals, managed
  identities): ``entra:principal/<objectId>`` (lowercase).
- Log Analytics workspaces are also reachable as
  ``loganalytics:<customerId>``.
- Hostnames (``x.azurecr.io``, ``x.vault.azure.net``, web app default
  host names, storage endpoints, ...) are registered as lowercase aliases.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from enum import Enum
from typing import Any, Mapping
from urllib.parse import urlparse

PRINCIPAL_PREFIX = "entra:principal/"
LOG_ANALYTICS_PREFIX = "loganalytics:"
ACR_PULL_ROLE_ID = "7f951dda-4ed3-4680-a7ca-43fe172d538d"

# Built-in role definition GUIDs -> names (used when ARG cannot join names)
BUILTIN_ROLES: dict[str, str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f6fb9d41c8d7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    ACR_PULL_ROLE_ID: "AcrPull",
    "8311e382-0749-4cb8-b61a-304f252e45ec": "AcrPush",
}

PRIVILEGED_ROLES = {
    "owner",
    "contributor",
    "user access administrator",
    "role based access control administrator",
    "key vault administrator",
    "virtual machine contributor",
    "storage account contributor",
    "azure kubernetes service cluster admin role",
    "azure kubernetes service rbac cluster admin",
}


# ---------------------------------------------------------------------------
# Identifier helpers
# ---------------------------------------------------------------------------

_RG_RE = re.compile(r"^(/subscriptions/[^/]+/resourceGroups/[^/]+)", re.IGNORECASE)
_SUB_RE = re.compile(r"^/subscriptions/([^/]+)", re.IGNORECASE)
_MG_RE = re.compile(r"^/providers/Microsoft\.Management/managementGroups/([^/]+)", re.IGNORECASE)
_GUID_TAIL_RE = re.compile(
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/?$"
)


def principal_ref(principal_id: Any) -> str | None:
    """Canonical identifier for an Entra principal object ID."""
    if not principal_id or not isinstance(principal_id, str):
        return None
    return f"{PRINCIPAL_PREFIX}{principal_id.strip().lower()}"


def subscription_ref(subscription_id: str) -> str:
    return f"/subscriptions/{subscription_id}"


def management_group_ref(name: str) -> str:
    return f"/providers/Microsoft.Management/managementGroups/{name}"


def normalize_scope(scope: Any) -> str | None:
    """Canonical form of an RBAC / policy scope (management groups rebuilt)."""
    if not isinstance(scope, str) or not scope:
        return None
    m = _MG_RE.match(scope)
    if m and scope.rstrip("/").count("/") == 4:
        return management_group_ref(m.group(1))
    if scope.strip() == "/":
        return "/"
    return scope.rstrip("/")


def subscription_of(resource_id: str | None) -> str | None:
    m = _SUB_RE.match(resource_id or "")
    return m.group(1) if m else None


def resource_group_of(resource_id: str | None) -> str | None:
    """``/subscriptions/<s>/resourceGroups/<rg>`` of a resource ID."""
    m = _RG_RE.match(resource_id or "")
    return m.group(1) if m else None


def resource_group_name(resource_id: str | None) -> str | None:
    """Bare resource group name of a resource ID."""
    rg = resource_group_of(resource_id)
    return rg.rsplit("/", 1)[-1] if rg else None


def _segments(resource_id: str) -> tuple[list[str], int]:
    parts = resource_id.split("/")
    lower = [p.lower() for p in parts]
    idx = -1
    for i in range(len(lower) - 1, -1, -1):
        if lower[i] == "providers":
            idx = i
            break
    return parts, idx


def parent_resource_id(resource_id: str | None) -> str | None:
    """Immediate parent of a nested (``/t1/n1/t2/n2``) or extension resource."""
    if not resource_id:
        return None
    parts, idx = _segments(resource_id.rstrip("/"))
    if idx < 0:
        return None
    tail = parts[idx + 2 :]  # after the namespace: type/name pairs
    if len(tail) >= 4 and len(tail) % 2 == 0:
        return "/".join(parts[: len(parts) - 2])
    if len(tail) == 2:
        prefix = parts[:idx]
        if any(p.lower() == "providers" for p in prefix):
            return "/".join(prefix)  # extension resource on another resource
    return None


def owner_resource_id(sub_resource_id: str | None) -> str | None:
    """Top-level resource owning a sub-resource (ipConfiguration, pool, ...)."""
    if not sub_resource_id or not isinstance(sub_resource_id, str):
        return None
    parts, idx = _segments(sub_resource_id)
    if idx < 0 or idx + 3 >= len(parts):
        return sub_resource_id
    return "/".join(parts[: idx + 4])


def host_of(url: Any) -> str | None:
    """Lowercase hostname of a URL or bare host."""
    if not isinstance(url, str) or not url.strip():
        return None
    value = url.strip()
    if "://" not in value:
        value = "https://" + value
    try:
        host = urlparse(value).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def registry_host(image: Any) -> str | None:
    """Registry host of a container image reference (None for Docker Hub)."""
    if not isinstance(image, str) or "/" not in image:
        return None
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first.lower()
    return None


def _docker_image(fx_version: Any) -> str | None:
    if isinstance(fx_version, str) and fx_version.upper().startswith("DOCKER|"):
        return fx_version.split("|", 1)[1].strip() or None
    return None


def _kql(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._\-]", "", value or "")


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------


def to_rest(obj: Any, depth: int = 0) -> Any:
    """Serialise an Azure SDK model (TypeSpec or msrest) to its REST JSON shape."""
    if depth > 40:
        return None
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, str):
        return str(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return None
    serialize = getattr(obj, "serialize", None)
    if callable(serialize) and not isinstance(obj, Mapping) and hasattr(obj, "_attribute_map"):
        try:
            return to_rest(serialize(keep_readonly=True), depth + 1)
        except Exception:  # pragma: no cover - defensive
            return None
    if isinstance(obj, Mapping):
        return {str(k): to_rest(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_rest(v, depth + 1) for v in obj]
    return str(obj)


_REDACT_KEYS = {
    "customdata",
    "userdata",
    "password",
    "adminpassword",
    "administratorloginpassword",
    "secret",
    "secretvalue",
    "securevalue",
    "connectionstring",
    "connectionstrings",
    "primarykey",
    "secondarykey",
    "accesskey",
    "accesskeys",
    "sastoken",
    "definition",
    "protectedsettings",
}
_MAX_STR = 4096
_MAX_LIST = 500


def sanitize(value: Any, depth: int = 0) -> Any:
    """Copy of a properties bag with secrets redacted and sizes bounded."""
    if depth > 16:
        return None
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            kl = key.lower()
            if kl in _REDACT_KEYS:
                out[key] = "<redacted>" if v not in (None, "", [], {}) else v
            elif kl in ("env", "environmentvariables") and isinstance(v, list):
                out[key] = [
                    {kk: vv for kk, vv in e.items() if kk in ("name", "secretRef")}
                    for e in v
                    if isinstance(e, dict)
                ]
            else:
                out[key] = sanitize(v, depth + 1)
        return out
    if isinstance(value, list):
        items = [sanitize(v, depth + 1) for v in value[:_MAX_LIST]]
        if len(value) > _MAX_LIST:
            items.append(f"<{len(value) - _MAX_LIST} more>")
        return items
    if isinstance(value, str) and len(value) > _MAX_STR:
        return value[:_MAX_STR] + "...<truncated>"
    return value


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """dict.get with a case-insensitive fallback (ARM key casing varies)."""
    if not isinstance(obj, dict):
        return default
    if key in obj:
        return obj[key]
    kl = key.lower()
    for k, v in obj.items():
        if isinstance(k, str) and k.lower() == kl:
            return v
    return default


def _path(obj: Any, *keys: str) -> Any:
    for key in keys:
        obj = _get(obj, key)
        if obj is None:
            return None
    return obj


def _rid(value: Any) -> str | None:
    if isinstance(value, dict):
        value = _get(value, "id")
    return value if isinstance(value, str) and value else None


def _rids(values: Any) -> list[str]:
    return [r for r in (_rid(v) for v in (values or [])) if r]


def _props(sub: Any) -> dict[str, Any]:
    """Properties of an embedded sub-resource (nested or already flattened)."""
    if not isinstance(sub, dict):
        return {}
    p = _get(sub, "properties")
    return p if isinstance(p, dict) else sub


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _lower(value: Any) -> str:
    return str(value).lower() if value is not None else ""


def _tags(tags: Any) -> dict[str, str]:
    if not isinstance(tags, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in tags.items()}
