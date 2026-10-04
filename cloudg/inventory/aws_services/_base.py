"""Shared plumbing for the deep AWS inventory collector mixins.

Every mixin in this package is combined with
:class:`cloudg.collectors.aws.AsyncAWSCollector` (see
:class:`cloudg.inventory.aws_deep.AWSDeepInventoryCollector`), so it can
rely on ``self._region``, ``self._account_id``, ``self._aio_config`` and
``self._get_aio_session()``.

Relationships are declared, not resolved, at collection time: a collector
only knows the *identifier* of what an asset talks to (an ARN, an ID, a
queue URL, an image URI). It records that as an entry in
``metadata["relations"]`` built with :func:`rel`, and the
:class:`~cloudg.inventory.linker.RelationshipLinker` later resolves the
identifier against every collected asset, across services, regions and
accounts, and emits the typed edge.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, AsyncIterator, Awaitable, Callable, Iterable
from urllib.parse import unquote

from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

logger = logging.getLogger(__name__)

# Max concurrent per-item describe calls inside one collector
_ITEM_CONCURRENCY = 8

_ARN_IN_TEXT_RE = re.compile(r"arn:aws[a-zA-Z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[^\s\"',}\]]+")


def rel(
    target: Any,
    edge: EdgeType,
    relationship: str | None = None,
    *,
    reverse: bool = False,
    description: str | None = None,
    **properties: Any,
) -> dict[str, Any] | None:
    """Declare a relationship from the owning asset to ``target``.

    Args:
        target: Any identifier of the other asset (ARN, ID, name, URL).
        edge: Coarse edge class.
        relationship: Fine-grained ontology relation name.
        reverse: The edge points from ``target`` to the owning asset.
        description: Human-readable explanation.
        **properties: Extra detail stored on the edge.

    Returns:
        The relation dict, or None when the target is empty.
    """
    if not target or not isinstance(target, str):
        return None
    out: dict[str, Any] = {"target": target, "edge": edge.value}
    if relationship:
        out["relationship"] = relationship
    if reverse:
        out["reverse"] = True
    if description:
        out["description"] = description
    if properties:
        out["properties"] = {k: v for k, v in properties.items() if v not in (None, "", [], {})}
    return out


def tag_dict(tags: Any) -> dict[str, str]:
    """Normalise the many AWS tag shapes into a flat dict."""
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    out: dict[str, str] = {}
    for t in tags:
        if not isinstance(t, dict):
            continue
        key = t.get("Key", t.get("key"))
        if key is not None:
            out[str(key)] = str(t.get("Value", t.get("value", "")))
    return out


def policy_document(doc: Any) -> dict[str, Any]:
    """Decode an IAM/resource policy that may be a dict, JSON or URL-encoded JSON."""
    if isinstance(doc, dict):
        return doc
    if not isinstance(doc, str) or not doc:
        return {}
    for candidate in (doc, unquote(doc)):
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            continue
    return {}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def policy_statements(doc: Any) -> list[dict[str, Any]]:
    return [s for s in as_list(policy_document(doc).get("Statement")) if isinstance(s, dict)]


def policy_principals(statement: dict[str, Any]) -> dict[str, list[str]]:
    """Principals of a statement as {"AWS": [...], "Service": [...], "Federated": [...]}."""
    principal = statement.get("Principal")
    if principal == "*":
        return {"AWS": ["*"]}
    if not isinstance(principal, dict):
        return {}
    return {k: [str(p) for p in as_list(v)] for k, v in principal.items()}


def condition_values(statement: dict[str, Any], *keys: str) -> list[str]:
    """Values of the given condition keys (case-insensitive) across operators."""
    wanted = {k.lower() for k in keys}
    out: list[str] = []
    for block in (statement.get("Condition") or {}).values():
        if not isinstance(block, dict):
            continue
        for key, val in block.items():
            if key.lower() in wanted:
                out.extend(str(v) for v in as_list(val))
    return out


def account_principal(principal: str) -> str | None:
    """Return the account ID for account-level principals (``123`` / ``...:root``)."""
    if re.fullmatch(r"\d{12}", principal):
        return principal
    m = re.fullmatch(r"arn:aws[a-zA-Z-]*:iam::(\d{12}):root", principal)
    return m.group(1) if m else None


def principal_ref(principal: str) -> str:
    """Canonical identifier for an AWS principal (accounts become root ARNs)."""
    acct = account_principal(principal)
    return f"arn:aws:iam::{acct}:root" if acct else principal


def arns_in(value: Any, limit: int = 200) -> list[str]:
    """Every ARN mentioned anywhere inside a (possibly nested) value."""
    found: list[str] = []
    seen: set[str] = set()

    def walk(v: Any, depth: int = 0) -> None:
        if depth > 12 or len(found) >= limit:
            return
        if isinstance(v, str):
            for m in _ARN_IN_TEXT_RE.findall(v):
                m = m.rstrip(".")
                if m not in seen:
                    seen.add(m)
                    found.append(m)
        elif isinstance(v, dict):
            for item in v.values():
                walk(item, depth + 1)
        elif isinstance(v, (list, tuple)):
            for item in v:
                walk(item, depth + 1)

    walk(value)
    return found


def identifier_refs(env: dict[str, Any] | None) -> list[str]:
    """Identifiers in environment-style key/value maps, without keeping values.

    Only values that are unmistakably resource identifiers (ARNs and AWS
    endpoint URLs) are returned, so secrets stored in plain environment
    variables never reach the inventory.
    """
    refs: list[str] = []
    for value in (env or {}).values():
        if not isinstance(value, str):
            continue
        v = value.strip()
        if v.startswith("arn:aws"):
            refs.append(v)
        elif v.startswith("https://sqs.") and ".amazonaws.com/" in v:
            refs.append(v)
    return refs


def resource_policy_relations(policy: Any, account_id: str | None) -> tuple[list[dict | None], bool]:
    """Invoker / grant relations from a resource policy, plus a 'public' flag.

    Service principals with a SourceArn condition become INVOKES edges from
    that source; AWS principals become GRANTS_ACCESS edges.
    """
    relations: list[dict | None] = []
    public = False
    for st in policy_statements(policy):
        if st.get("Effect") != "Allow":
            continue
        principals = policy_principals(st)
        sources = condition_values(st, "aws:SourceArn", "AWS:SourceArn")
        for svc in principals.get("Service", []):
            if sources:
                for src in sources:
                    relations.append(
                        rel(src.rstrip("*").rstrip("/").rstrip(":"), EdgeType.INVOKES, "TRIGGERED_BY", reverse=True,
                            description=f"{svc} may invoke", service=svc)
                    )
        for p in principals.get("AWS", []):
            if p == "*":
                if not st.get("Condition"):
                    public = True
                continue
            ref = principal_ref(p)
            relations.append(
                rel(ref, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True,
                    description="resource policy grant",
                    cross_account=bool(account_id and f":{account_id}:" not in ref))
            )
    return relations, public


async def gather_limited(
    factories: Iterable[Callable[[], Awaitable[Any]]], limit: int = _ITEM_CONCURRENCY
) -> list[Any]:
    """Run coroutine factories with bounded concurrency; failures become None."""
    sem = asyncio.Semaphore(limit)

    async def run(factory: Callable[[], Awaitable[Any]]) -> Any:
        async with sem:
            try:
                return await factory()
            except Exception as exc:
                logger.debug("Item collection failed: %s", exc)
                return None

    return await asyncio.gather(*(run(f) for f in factories))


def error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None) or {}
    return str((response.get("Error") or {}).get("Code", type(exc).__name__))


class AWSServiceMixin:
    """Helpers shared by every deep-collector mixin."""

    # Provided by AsyncAWSCollector, which always follows the mixins in the
    # MRO (so no stubs for its methods may be defined here).
    _region: str
    _account_id: str | None
    _aio_config: Any

    def _client(self, service: str, region: str | None = None) -> Any:
        return self._get_aio_session().client(  # type: ignore[attr-defined]
            service, region_name=region or self._region, config=self._aio_config
        )

    async def _paginate(
        self, client: Any, operation: str, result_key: str, **kwargs: Any
    ) -> AsyncIterator[Any]:
        """Yield items of ``result_key`` across all pages of ``operation``."""
        paginator = client.get_paginator(operation)
        async for page in paginator.paginate(**kwargs):
            for item in page.get(result_key, []) or []:
                yield item

    async def _pages(
        self,
        call: Any,
        result_key: str,
        token_in: str = "NextToken",
        token_out: str | None = None,
        max_pages: int = 1000,
        **kwargs: Any,
    ) -> AsyncIterator[Any]:
        """Manual token pagination for operations without a botocore
        paginator (``_paginate`` raises OperationNotPageableError on them).

        Args:
            call: Bound client method, e.g. ``client.list_services``.
            result_key: Response key holding the items.
            token_in: Request parameter carrying the token.
            token_out: Response key holding the next token (default token_in).
        """
        token_out = token_out or token_in
        token = None
        for _ in range(max_pages):
            params = dict(kwargs)
            if token:
                params[token_in] = token
            resp = await call(**params)
            for item in resp.get(result_key, []) or []:
                yield item
            token = resp.get(token_out)
            if not token:
                return

    def _arn(self, service: str, resource: str, region: str | None = None) -> str:
        reg = self._region if region is None else region
        return f"arn:aws:{service}:{reg}:{self._account_id}:{resource}"

    def _account_ref(self) -> str:
        return f"arn:aws:iam::{self._account_id}:root"

    def _asset(
        self,
        *,
        arn: str,
        name: str,
        asset_type: AssetType,
        region: str | None = None,
        tags: Any = None,
        metadata: dict[str, Any] | None = None,
        relations: Iterable[dict[str, Any] | None] = (),
        raw: dict[str, Any] | None = None,
        exposed: bool = False,
        aliases: Iterable[str | None] = (),
    ) -> CloudAsset:
        md = dict(metadata or {})
        rels = [r for r in relations if r]
        if rels:
            md["relations"] = rels
        alias_list = [a for a in aliases if a]
        if alias_list:
            md["aliases"] = alias_list
        return CloudAsset(
            arn=arn,
            name=name or arn,
            asset_type=asset_type,
            provider=CloudProvider.AWS,
            region=self._region if region is None else region,
            account_id=self._account_id,
            tags=tag_dict(tags),
            metadata=md,
            raw_data=raw or {},
            is_internet_exposed=exposed,
        )

    def _disabled_asset(
        self, service: str, asset_type: AssetType, label: str, reason: str = "not enabled"
    ) -> CloudAsset:
        """Placeholder for a security service that is not deployed in this
        account/region, so coverage gaps show up on the map."""
        return self._asset(
            arn=f"cloudg:aws:{service}:{self._region}:{self._account_id}:not-enabled",
            name=f"{label} ({reason})",
            asset_type=asset_type,
            metadata={"security_service": service, "enabled": False, "status": reason},
            aliases=[self._security_alias(service)],
        )

    def _security_alias(self, service: str) -> str:
        """Stable alias for 'the <service> deployment in this account/region'."""
        return f"aws-security:{service}:{self._region}:{self._account_id}"
