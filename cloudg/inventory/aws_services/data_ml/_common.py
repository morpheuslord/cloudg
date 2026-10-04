"""Constants and helpers shared by the data / analytics / messaging / ML
collectors."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from fnmatch import fnmatchcase
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import urlparse

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    as_list,
    error_code,
    gather_limited,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.schema.models import CloudAsset, EdgeType

# Log under the package name, as the single module did before the split.
logger = logging.getLogger(__name__.rsplit(".", 1)[0])

Relations = list[dict[str, Any] | None]

# API Gateway invoke host: <api-id>.execute-api.<region>.amazonaws.com
_EXECUTE_API_HOST_RE = re.compile(r"[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com(\.cn)?")

_MAX_TRANSFER_USERS = 200  # per server
_MAX_LF_PERMISSIONS = 2000  # per region
_MAX_TABLES_COUNTED = 1000  # per Glue database
_AGENT_VERSION = "DRAFT"  # working copy of a Bedrock agent

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_S3_URI_RE = re.compile(r"^s3[an]?://([^/]+)", re.I)
_FS_ID_RE = re.compile(r"\b(fs-[0-9a-f]{8,17})\b")
_EMR_ACTIVE_STATES = ["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]

# Glue job arguments that carry S3 locations (values are never stored)
_GLUE_ARG_READS = ("--extra-py-files", "--extra-jars", "--extra-files")
_GLUE_ARG_WRITES = ("--TempDir",)
_GLUE_ARG_LOGS = ("--spark-event-logs-path",)


def _kms_ref(key: Any) -> str | None:
    """A KMS key identifier worth linking (drops 'auto', AWS-owned markers)."""
    if not isinstance(key, str) or not key:
        return None
    if key.startswith("arn:") or key.startswith("alias/") or _UUID_RE.match(key):
        return key
    return None


def _bucket_arn(uri: Any) -> str | None:
    """Bucket ARN for an ``s3://bucket/key`` URI or S3 ARN."""
    if not isinstance(uri, str) or not uri:
        return None
    m = _S3_URI_RE.match(uri.strip())
    if m:
        return f"arn:aws:s3:::{m.group(1)}"
    if uri.startswith("arn:aws:s3:::"):
        return uri.split("/", 1)[0]
    return None


def _host(url: Any) -> str | None:
    """Hostname of a URL (never user-info, path or query)."""
    if not isinstance(url, str) or not url:
        return None
    candidate = url[len("jdbc:") :] if url.startswith("jdbc:") else url
    if "://" not in candidate:
        candidate = f"//{candidate}"
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _document(doc: Any) -> Any:
    """Parse a JSON document that may already be decoded."""
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except ValueError:
            return None
    return doc


def _aoss_match(resources: Any, name: str, kinds: tuple[str, ...]) -> bool:
    """Whether OpenSearch Serverless resource patterns cover a collection."""
    for res in as_list(resources):
        if not isinstance(res, str):
            continue
        kind, _, rest = res.partition("/")
        if kind not in kinds:
            continue
        if fnmatchcase(name, rest.split("/", 1)[0]):
            return True
    return False


def _linkable_principal(principal: Any) -> bool:
    """Lake Formation / AOSS principals that resolve to an IAM identity or
    account (skips groups such as IAM_ALLOWED_PRINCIPALS)."""
    return isinstance(principal, str) and (principal.startswith("arn:") or principal.isdigit())


def _permission_grant_rels(
    grants: dict[str, set[str]], description: str, limit: int | None = None
) -> Relations:
    """GRANTS_ACCESS relations (principal -> resource) carrying permissions."""
    return [
        rel(
            principal,
            EdgeType.GRANTS_ACCESS,
            "POLICY_ALLOWS_ACTION",
            reverse=True,
            description=description,
            permissions=sorted(perms)[:limit],
        )
        for principal, perms in grants.items()
    ]


def _name_tag(tags: Any) -> str | None:
    """Value of the ``Name`` tag in an AWS ``[{Key, Value}]`` tag list."""
    return next((t.get("Value") for t in tags or [] if t.get("Key") == "Name"), None)


async def _gather_details(
    items: Iterable[Any], detail: Callable[[Any], Awaitable[Any]]
) -> list[Any]:
    """Run ``detail`` per item with bounded concurrency, dropping failures."""
    results = await gather_limited([lambda x=x: detail(x) for x in items])
    return [a for a in results if a]


class DataMLHelpersMixin(AWSServiceMixin):
    """Reference builders shared by the data / ML collector mixins."""

    def _dm_role_ref(self, role: Any) -> str | None:
        if not isinstance(role, str) or not role:
            return None
        return role if role.startswith("arn:") else f"arn:aws:iam::{self._account_id}:role/{role}"

    def _profile_ref(self, profile: Any) -> str | None:
        if not isinstance(profile, str) or not profile:
            return None
        if profile.startswith("arn:"):
            return profile
        return f"arn:aws:iam::{self._account_id}:instance-profile/{profile}"

    def _log_group_ref(self, group: Any, region: str | None = None) -> str | None:
        if not isinstance(group, str) or not group:
            return None
        if group.startswith("arn:"):
            return group.removesuffix(":*")
        return self._arn("logs", f"log-group:{group}", region)

    @staticmethod
    def _subnet_rels(subnets: Any) -> list[dict[str, Any] | None]:
        return [
            rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
            for s in as_list(subnets)
        ]

    @staticmethod
    def _grant_rels(policy: Any, description: str) -> tuple[list[dict[str, Any] | None], bool]:
        """GRANTS_ACCESS relations (principal -> resource) from a resource
        policy, plus whether it allows any principal unconditionally."""
        relations: list[dict[str, Any] | None] = []
        public = False
        seen: set[str] = set()
        for st in policy_statements(policy):
            if st.get("Effect") != "Allow":
                continue
            for p in policy_principals(st).get("AWS", []):
                if p == "*":
                    public = public or not st.get("Condition")
                    continue
                ref = principal_ref(p)
                if ref in seen:
                    continue
                seen.add(ref)
                relations.append(
                    rel(
                        ref,
                        EdgeType.GRANTS_ACCESS,
                        "POLICY_ALLOWS_ACTION",
                        reverse=True,
                        description=description,
                        actions=as_list(st.get("Action"))[:20],
                    )
                )
        return relations, public

    async def _gather_parts(
        self, label: str, parts: dict[str, Callable[[], Awaitable[list[CloudAsset]]]]
    ) -> list[CloudAsset]:
        """Run independent sub-collectors; raise only when all of them fail."""
        names = list(parts)
        results = await asyncio.gather(*(parts[n]() for n in names), return_exceptions=True)
        assets: list[CloudAsset] = []
        failures: dict[str, Exception] = {}
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                failures[name] = result
            elif isinstance(result, BaseException):
                raise result
            else:
                assets.extend(result)
        if failures and len(failures) == len(names):
            raise next(iter(failures.values()))
        for name, exc in failures.items():
            logger.info("%s: %s collection failed (%s): %s", label, name, error_code(exc), exc)
        return assets

    async def _lf_permissions(self, lf: Any) -> list[dict]:
        out: list[dict] = []
        async for p in self._pages(
            lf.list_permissions,
            "PrincipalResourcePermissions",
            max_pages=_MAX_LF_PERMISSIONS // 100 + 1,
            MaxResults=100,
        ):
            out.append(p)
            if len(out) >= _MAX_LF_PERMISSIONS:
                break
        return out
