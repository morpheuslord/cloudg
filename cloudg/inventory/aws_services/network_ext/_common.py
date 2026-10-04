"""Limits, patterns and helpers shared by the extended network collectors."""

from __future__ import annotations

import logging
import re
from typing import Any, Awaitable, Callable

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    error_code,
    gather_limited,
    policy_principals,
    policy_statements,
)
from cloudg.inventory.aws_services.platform import _dns
from cloudg.schema.models import CloudAsset

# One logger for the whole package, named like the original single module.
logger = logging.getLogger(__package__)

_MAX_TGW_ROUTES = 200
_MAX_PREFIX_ENTRIES = 50
_MAX_RULES_PER_LISTENER = 100
_MAX_LIST_METADATA = 100

_LAMBDA_URI_RE = re.compile(r"functions/(arn:aws[^/]+)/invocations")
_S3_ORIGIN_RE = re.compile(r"^([a-z0-9][a-z0-9.\-]*?)\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$")
_EXECUTE_API_RE = re.compile(r"^([a-z0-9]{10})\.execute-api\.[a-z0-9-]+\.amazonaws\.com$")
_COGNITO_ISSUER_RE = re.compile(
    r"^https://cognito-idp\.[a-z0-9-]+\.amazonaws\.com/([\w-]+_[0-9A-Za-z]+)"
)
_S3_URI_RE = re.compile(r"^s3://([^/]+)")

_GONE_STATES = {"deleted", "deleting"}

Section = Callable[[], Awaitable[list[CloudAsset] | None]]


def _unique(relations: list[dict | None]) -> list[dict]:
    """Drop empty and duplicate (target, edge, direction) relations."""
    seen: set[tuple[Any, ...]] = set()
    out: list[dict] = []
    for r in relations:
        if not r:
            continue
        key = (r["target"], r["edge"], r.get("reverse", False))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _name_tag(tags: Any, default: str) -> str:
    for t in tags or []:
        if isinstance(t, dict) and t.get("Key") == "Name" and t.get("Value"):
            return str(t["Value"])
    return default


def _policy_is_public(policy: Any) -> bool:
    """True when an Allow statement grants ``*`` without any condition."""
    for st in policy_statements(policy):
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        if "*" in policy_principals(st).get("AWS", []):
            return True
    return False


def _bucket_from_domain(domain: str) -> str | None:
    m = _S3_ORIGIN_RE.match(_dns(domain))
    return m.group(1) if m else None


def _ec2_arn(region: str | None, owner: str | None, resource: str, rid: str | None) -> str | None:
    """Full EC2 ARN for a resource in a (possibly other) account/region, so
    the linker can resolve it or materialise the external account."""
    if not rid:
        return None
    if region and owner and owner.isdigit():
        return f"arn:aws:ec2:{region}:{owner}:{resource}/{rid}"
    return rid


def section(name: str, fn: Callable[..., Awaitable[Any]], *args: Any) -> Section:
    """Bind ``fn(*args)`` as a listing section named ``name`` (the name is
    what ``_nx_sections`` logs when the section is skipped)."""

    async def run() -> Any:
        return await fn(*args)

    run.__name__ = name
    return run


class NetworkExtBase(AWSServiceMixin):
    """Section and fan-out helpers of the extended network collectors."""

    async def _nx_sections(self, *sections: Section) -> list[CloudAsset]:
        """Run independent listing sections of one collector.

        A failing section is logged and skipped; the collector only fails
        (raises) when every section failed, so coverage reports it.
        """
        assets: list[CloudAsset] = []
        errors: list[BaseException] = []
        for sec in sections:
            try:
                assets.extend(await sec() or [])
            except Exception as exc:
                errors.append(exc)
                logger.info("%s skipped: %s", getattr(sec, "__name__", "section"), error_code(exc))
        if errors and len(errors) == len(sections):
            raise errors[0]
        return assets

    async def _nx_each(
        self, detail: Callable[..., Awaitable[Any]], items: list[Any], *args: Any
    ) -> list[CloudAsset]:
        """``detail(*args, item)`` per item with bounded concurrency; failed
        items are dropped."""
        results = await gather_limited([lambda i=i: detail(*args, i) for i in items])
        return [a for a in results if a]

    async def _nx_each_flat(
        self, detail: Callable[..., Awaitable[Any]], items: list[Any], *args: Any
    ) -> list[CloudAsset]:
        """Like ``_nx_each`` for details returning lists of assets."""
        out: list[CloudAsset] = []
        for res in await gather_limited([lambda i=i: detail(*args, i) for i in items]):
            out.extend(res or [])
        return out

    async def _nx_group(
        self, client: Any, page: tuple[str, str], field: str, label: str
    ) -> dict[str, list[dict]]:
        """Group the items of a paginated listing by ``field``; a failed
        listing is logged and yields what was gathered so far."""
        grouped: dict[str, list[dict]] = {}
        try:
            async for item in self._paginate(client, *page):
                grouped.setdefault(item.get(field) or "", []).append(item)
        except Exception as exc:
            logger.debug("%s listing failed: %s", label, exc)
        return grouped
