"""Prowler OCSF records (``prowler <provider> -M json-ocsf``, ``*.ocsf.json``).

Prowler 4 and later write OCSF Detection Finding records by default. They
carry the same facts as the ASFF records :class:`~cloudg.scanners.prowler.ProwlerScanner`
has always read, under different keys:

- status: ``status_code`` (``PASS``, ``FAIL``, ``MANUAL``); a muted finding
  has ``status`` ``Suppressed``;
- severity: ``severity`` (``Critical`` ... ``Informational``);
- check: ``metadata.event_code`` (the Prowler check name), and the finding
  id ``finding_info.uid`` (``prowler-<provider>-<check>-<account>-...``);
- resource: ``resources[0].uid`` (the ARN or cloud resource id), else its
  ``name``;
- compliance: the keys of ``unmapped.compliance`` (``CIS-2.0``,
  ``NIST-800-53-Revision-5`` ...).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cloudg.normaliser import prowler_check_id
from cloudg.schema.models import Finding, Severity

# Top-level keys only OCSF records have (an ASFF record has none of them)
OCSF_KEYS = frozenset({"finding_info", "class_uid", "category_uid", "type_uid", "severity_id"})


def is_ocsf_record(item: Any) -> bool:
    """Whether ``item`` is one OCSF record rather than an ASFF finding."""
    if not isinstance(item, dict) or "ProductArn" in item or "Findings" in item:
        return False
    return bool(OCSF_KEYS & set(item))


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def ocsf_status(item: dict[str, Any]) -> str:
    """The record's check status, upper case: PASS, FAIL, MANUAL or ""."""
    status = str(item.get("status_code") or "").upper()
    if not status and str(item.get("status") or "").upper() in ("PASS", "FAIL", "MANUAL"):
        # Early Prowler 4 releases put the check status in ``status``
        status = str(item["status"]).upper()
    return status


def ocsf_check_id(item: dict[str, Any]) -> str:
    """The Prowler check name of an OCSF record, or ""."""
    check = str(_dict(item.get("metadata")).get("event_code") or "").strip()
    return check or prowler_check_id(_dict(item.get("finding_info")).get("uid"))


def _source_finding_id(item: dict[str, Any], check: str, resource: str) -> str:
    """A Prowler-style finding id that names the check.

    ``finding_info.uid`` when it already starts ``prowler-...-<check>``;
    otherwise ``prowler-<check>-<account>-<region>-<hash>``, the shape of
    a Prowler ASFF ``Id``, so dedupe and compliance mapping read the check
    the same way for both formats.
    """
    uid = str(_dict(item.get("finding_info")).get("uid") or "")
    if not check or prowler_check_id(uid) == check:
        return uid
    cloud = _dict(item.get("cloud"))
    account = str(_dict(cloud.get("account")).get("uid") or "unknown")
    region = str(cloud.get("region") or "global")
    digest = hashlib.sha256((uid or resource).encode()).hexdigest()[:9]
    return f"prowler-{check}-{account}-{region}-{digest}"


def parse_ocsf_record(
    item: dict[str, Any],
    severity_map: dict[str, Severity],
    compliance_map: dict[str, str],
) -> Finding | None:
    """Convert one failing (or manual) OCSF record into a :class:`Finding`.

    Returns None for a passing record, as the ASFF parser does; the caller
    collects passed checks with :func:`ocsf_status` / :func:`ocsf_check_id`.

    Args:
        item: The OCSF record.
        severity_map: Lower-case Prowler severity label to :class:`Severity`.
        compliance_map: Lower-case substring of a compliance key to the
            framework name cloudg uses (``cis`` to ``CIS`` ...).
    """
    if ocsf_status(item) == "PASS":
        return None

    info = _dict(item.get("finding_info"))
    severity = severity_map.get(str(item.get("severity") or "").lower(), Severity.MEDIUM)

    resources = item.get("resources") or []
    first = _dict(resources[0]) if isinstance(resources, list) and resources else {}
    resource = str(first.get("uid") or first.get("name") or "")
    arn = str(first.get("uid") or "")

    frameworks: list[str] = []
    for key in _dict(_dict(item.get("unmapped")).get("compliance")):
        for prefix, framework in compliance_map.items():
            if prefix in str(key).lower():
                if framework not in frameworks:
                    frameworks.append(framework)
                break

    check = ocsf_check_id(item)
    evidence = item.get("status_detail") or item.get("message") or ""
    return Finding(
        resource_id=resource,
        resource_arn=arn,
        severity=severity,
        title=str(info.get("title") or check or "Prowler finding"),
        description=str(info.get("desc") or item.get("risk_details") or ""),
        evidence=(evidence if isinstance(evidence, str) else json.dumps(evidence, default=str))[
            :1000
        ],
        remediation=str(_dict(item.get("remediation")).get("desc") or ""),
        source_tool="prowler",
        source_finding_id=_source_finding_id(item, check, resource),
        compliance_frameworks=frameworks,
        is_suppressed=str(item.get("status") or "").lower() == "suppressed",
    )
