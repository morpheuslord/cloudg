"""Reference helpers shared by the extractors added for AWS depth parity.

Each helper turns one GCP reference shape into the Cloud Asset Inventory
full resource name the linker indexes, or returns None.
"""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.gcp_relations.names import full_name, url_alias

_CRM = "//cloudresourcemanager.googleapis.com/"
_BQ_DOTTED_RE = re.compile(r"^(?:bq://)?([^.:/\s]+)[.:]([^.\s/]+)(?:\.([^.\s/]+))?$")
_BQ_PATH_RE = re.compile(r"projects/([^/]+)/datasets/([^/]+)(?:/tables/([^/]+))?")
_WORKFLOW_EXEC_RE = re.compile(
    r"^https://workflowexecutions\.googleapis\.com/v\d[^/]*/"
    r"(projects/[^/]+/locations/[^/]+/workflows/[^/:]+)"
)
_RUN_JOB_V2_RE = re.compile(
    r"^https://run\.googleapis\.com/v2/(projects/[^/]+/locations/[^/]+/jobs/[^/:]+)"
)
_RUN_JOB_V1_RE = re.compile(
    r"^https://([a-z0-9-]+)-run\.googleapis\.com/apis/run\.googleapis\.com/v1/"
    r"namespaces/([^/]+)/jobs/([^/:]+)"
)
_LB_SERVICE_RE = re.compile(r"/locations/([^/]+)/backendServices/")


def crm_ref(value: Any) -> str | None:
    """Project / folder / organization (``projects/x``, ``folders/1``, bare id) as a full name."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.startswith("//"):
        return s
    if re.fullmatch(r"(projects|folders|organizations)/[^/]+", s):
        return f"{_CRM}{s}"
    if re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]|\d+", s):
        return f"{_CRM}projects/{s}"
    return None


def parent_of(name: str, segment: str) -> str | None:
    """``name`` cut before ``/<segment>/`` (the parent resource), or None."""
    marker = f"/{segment}/"
    if not isinstance(name, str) or marker not in name:
        return None
    return name.split(marker, 1)[0]


def gcs_ref(value: Any) -> str | None:
    """Cloud Storage bucket of a ``gs://`` URI, bucket name or storage URL."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.startswith("gs://"):
        return full_name(s)
    if "://" in s or s.startswith("//"):
        return full_name(s)
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", s):
        return f"//storage.googleapis.com/{s}"
    return None


def bq_ref(value: Any, default_project: str | None = None) -> str | None:
    """BigQuery dataset or table from ``p.d.t``, ``p:d.t``, ``bq://p.d.t`` or a path."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip().strip("`")
    m = _BQ_PATH_RE.search(s)
    if m:
        project, dataset, table = m.groups()
    else:
        m = _BQ_DOTTED_RE.match(s)
        if not m:
            return None
        project, dataset, table = m.groups()
    if not project:
        project = default_project
    if not project or not dataset:
        return None
    out = f"//bigquery.googleapis.com/projects/{project}/datasets/{dataset}"
    return f"{out}/tables/{table}" if table else out


def bq_dataset_ref(project: Any, dataset: Any) -> str | None:
    if isinstance(project, str) and project and isinstance(dataset, str) and dataset:
        return f"//bigquery.googleapis.com/projects/{project}/datasets/{dataset}"
    return None


def url_target(uri: Any) -> str | None:
    """What an HTTP target URL calls.

    Workflow execution and Cloud Run job ``:run`` URLs map to the workflow or
    job; anything else is reduced to ``https://host`` (the alias Cloud Run,
    Cloud Functions and API Gateway assets carry).
    """
    if not isinstance(uri, str) or not uri:
        return None
    m = _WORKFLOW_EXEC_RE.match(uri)
    if m:
        return f"//workflows.googleapis.com/{m.group(1)}"
    m = _RUN_JOB_V2_RE.match(uri)
    if m:
        return f"//run.googleapis.com/{m.group(1)}"
    m = _RUN_JOB_V1_RE.match(uri)
    if m:
        region, project, job = m.groups()
        return f"//run.googleapis.com/projects/{project}/locations/{region}/jobs/{job}"
    return url_alias(uri)


def backend_service_ref(value: Any) -> str | None:
    """Backend service named the Network Services way (``.../locations/global/...``)."""
    ref = full_name(value, "compute")
    if not ref:
        return None
    m = _LB_SERVICE_RE.search(ref)
    if not m:
        return ref
    loc = m.group(1)
    repl = "/global/backendServices/" if loc == "global" else f"/regions/{loc}/backendServices/"
    return ref[: m.start()] + repl + ref[m.end() :]


def host_target(host: Any) -> str | None:
    """``https://host`` for a bare host name (ports and paths dropped)."""
    if not isinstance(host, str) or not host:
        return None
    if "://" in host:
        return url_alias(host)
    h = host.strip().split("/", 1)[0].split(":", 1)[0].lower()
    return f"https://{h}" if h and "." in h else None


def secret_version_ref(value: Any) -> str | None:
    """Secret Manager secret of a secret (version) name."""
    if not isinstance(value, str) or "/secrets/" not in value:
        return None
    return full_name(value.split("/versions/", 1)[0], "secretmanager")


__all__ = [
    "backend_service_ref",
    "bq_dataset_ref",
    "bq_ref",
    "crm_ref",
    "gcs_ref",
    "host_target",
    "parent_of",
    "secret_version_ref",
    "url_target",
]
