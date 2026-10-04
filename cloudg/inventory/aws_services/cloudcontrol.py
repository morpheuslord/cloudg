"""Breadth sweep over the AWS Cloud Control API.

The Resource Groups Tagging API only returns resources that are (or were)
tagged, so a never-tagged resource of a service without a dedicated
collector would be missing from the map. Cloud Control's
``ListResources`` enumerates the live resources of every resource type
that has a CloudFormation *list* handler (800+ types), tagged or not.

Reference data (which types the deep collectors already cover, which are
account-wide, how types classify, which fields are secret-bearing) is in
``cloudg/inventory/catalogs/aws_cloudcontrol.yaml``; extend that file, not
this module.

How it runs:

1. Listable types are discovered once per process from the CloudFormation
   registry (``ListTypes`` + ``DescribeType``: types whose schema has a
   ``list`` handler that needs no parent identifiers) and cached on disk
   for a week (``$CLOUDG_CACHE_DIR`` or ``~/.cache/cloudg``).
2. Types already covered by a dedicated deep collector are skipped, and
   account-wide types (IAM, CloudFront, Route 53, Organizations, ...) run
   only in the primary region.
3. Each remaining type is listed with bounded concurrency; unsupported or
   failing types are skipped and counted, never fatal.

Every hit becomes an asset with ``metadata.discovered_via =
"cloud-control"``, the CloudFormation type, its identifier and its
properties (with secret-bearing fields removed). The relationship
linker's generic pass then links any ARN or ID those properties mention.

IAM: ``cloudformation:ListTypes``, ``cloudformation:DescribeType``,
``cloudformation:ListResources`` (Cloud Control) plus each type's own
read/list permissions; ``ReadOnlyAccess`` covers the common cases.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from cloudg.coverage import ServiceStatus
from cloudg.inventory.aws_services._base import AWSServiceMixin, error_code, gather_limited
from cloudg.inventory.catalogs import asset_type_map, flatten, load_catalog
from cloudg.schema.models import AssetType, CloudAsset

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 7 * 24 * 3600
_MAX_RESOURCES_PER_TYPE = 5000

# Reference data (covered types, global prefixes, type map, per-type
# sensitive fields) lives in catalogs/aws_cloudcontrol.yaml.
_CATALOG = load_catalog("aws_cloudcontrol")
COVERED_TYPES: set[str] = set(flatten(_CATALOG.get("covered_types")))
_GLOBAL_PREFIXES: tuple[str, ...] = tuple(_CATALOG.get("global_prefixes") or ())
_TYPE_MAP: dict[str, AssetType] = asset_type_map(_CATALOG.get("asset_types"), "aws_cloudcontrol")
_SENSITIVE_BY_TYPE: dict[str, set[str]] = {
    t: set(fields or []) for t, fields in (_CATALOG.get("sensitive_fields") or {}).items()
}

# Property names never copied into the inventory (any depth, case-insensitive).
_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret(?!sarn|arn|manager)|token|privatekey|private_key|credential|"
    r"apikey|api_key|authorization|connectionstring|certificatebody|keymaterial|"
    r"environmentvariables|^environment$|userdata)",
    re.IGNORECASE,
)

_types_cache: list[dict[str, Any]] | None = None
_types_lock: asyncio.Lock | None = None
_types_lock_loop: Any = None


def _cache_path() -> Path:
    base = os.environ.get("CLOUDG_CACHE_DIR") or str(Path.home() / ".cache" / "cloudg")
    return Path(base) / "cloudcontrol-types.json"


def _load_disk_cache() -> list[dict[str, Any]] | None:
    try:
        data = json.loads(_cache_path().read_text())
        if time.time() - float(data.get("fetched_at", 0)) < _CACHE_TTL_SECONDS:
            types = data.get("types")
            return types if isinstance(types, list) and types else None
    except (OSError, ValueError, TypeError):
        return None
    return None


def _save_disk_cache(types: list[dict[str, Any]]) -> None:
    try:
        path = _cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"fetched_at": time.time(), "types": types}))
    except OSError as exc:
        logger.debug("Could not write the Cloud Control type cache: %s", exc)


def redact(value: Any, type_name: str = "", depth: int = 0) -> Any:
    """Drop secret-bearing fields from Cloud Control properties."""
    if depth > 12:
        return None
    if isinstance(value, dict):
        blocked = _SENSITIVE_BY_TYPE.get(type_name, set()) if depth == 0 else set()
        return {
            k: redact(v, type_name, depth + 1)
            for k, v in value.items()
            if k not in blocked and not _SENSITIVE_KEY_RE.search(str(k))
        }
    if isinstance(value, list):
        return [redact(v, type_name, depth + 1) for v in value]
    return value


def is_global_type(type_name: str) -> bool:
    return type_name.startswith(_GLOBAL_PREFIXES)


def _type_matches(type_name: str, patterns: list[str]) -> bool:
    return any(type_name == p or type_name.startswith(p) for p in patterns)


class CloudControlCollectorsMixin(AWSServiceMixin):
    """Cloud Control API breadth sweep (task ``cloud_control``)."""

    _cloud_control: bool = True
    _cloud_control_concurrency: int = 6
    _cloud_control_types: list[str] = []
    _cloud_control_exclude: list[str] = []
    _is_primary_region: bool = True
    coverage: Any

    async def _cc_listable_types(self) -> list[dict[str, Any]]:
        """Resource types with a parent-free list handler (cached)."""
        global _types_cache, _types_lock, _types_lock_loop
        if _types_cache is not None:
            return _types_cache
        loop = asyncio.get_running_loop()
        if _types_lock is None or _types_lock_loop is not loop:
            _types_lock, _types_lock_loop = asyncio.Lock(), loop
        async with _types_lock:
            if _types_cache is not None:
                return _types_cache
            cached = _load_disk_cache()
            if cached:
                _types_cache = cached
                return cached

            names: list[str] = []
            async with self._client("cloudformation") as cfn:
                for provisioning in ("FULLY_MUTABLE", "IMMUTABLE"):
                    async for summary in self._paginate(
                        cfn,
                        "list_types",
                        "TypeSummaries",
                        Type="RESOURCE",
                        Visibility="PUBLIC",
                        ProvisioningType=provisioning,
                        DeprecatedStatus="LIVE",
                        Filters={"Category": "AWS_TYPES"},
                    ):
                        if summary.get("TypeName"):
                            names.append(summary["TypeName"])

                async def describe(name: str) -> dict[str, Any] | None:
                    resp = await cfn.describe_type(Type="RESOURCE", TypeName=name)
                    schema = json.loads(resp.get("Schema") or "{}")
                    handler = (schema.get("handlers") or {}).get("list")
                    if not handler:
                        return None
                    required = (handler.get("handlerSchema") or {}).get("required") or []
                    return {"type": name, "requires": list(required)}

                described = await gather_limited(
                    [lambda n=n: describe(n) for n in sorted(set(names))], limit=8
                )
            types = [d for d in described if d]
            logger.info("Cloud Control: %d of %d resource types are listable", len(types), len(names))
            if types:
                _save_disk_cache(types)
            _types_cache = types
            return types

    def _cc_selected(self, types: list[dict[str, Any]]) -> list[str]:
        selected = []
        for entry in types:
            name = entry["type"]
            if entry.get("requires"):
                continue  # needs a parent identifier
            if name in COVERED_TYPES:
                continue
            if is_global_type(name) and not self._is_primary_region:
                continue
            if self._cloud_control_types and not _type_matches(name, self._cloud_control_types):
                continue
            if self._cloud_control_exclude and _type_matches(name, self._cloud_control_exclude):
                continue
            selected.append(name)
        return selected

    def _cc_asset(self, type_name: str, description: dict[str, Any]) -> CloudAsset:
        identifier = str(description.get("Identifier", ""))
        try:
            props = json.loads(description.get("Properties") or "{}")
        except ValueError:
            props = {}
        if not isinstance(props, dict):
            props = {}
        short = type_name.rsplit("::", 1)[-1]
        arn = props.get("Arn") or props.get(f"{short}Arn")
        if not (isinstance(arn, str) and arn.startswith("arn:")):
            arn = identifier if identifier.startswith("arn:") else None
        region = "global" if is_global_type(type_name) else self._region
        if not arn:
            arn = f"cloudcontrol:{type_name}:{region}:{self._account_id}:{identifier}"
        name = props.get("Name") or props.get(f"{short}Name") or identifier
        asset_type = _TYPE_MAP.get(type_name)
        if asset_type is None:
            from cloudg.inventory.aws_deep import asset_type_from_arn

            asset_type = asset_type_from_arn(arn) if arn.startswith("arn:") else AssetType.OTHER
        return self._asset(
            arn=arn,
            name=str(name),
            asset_type=asset_type,
            region=region,
            tags=props.get("Tags"),
            metadata={
                "discovered_via": "cloud-control",
                "resource_type": type_name,
                "identifier": identifier,
                "service": type_name.split("::")[1].lower() if type_name.count("::") >= 2 else "",
                "properties": redact(props, type_name),
            },
            aliases=[identifier] if identifier and identifier != arn else [],
        )

    async def _collect_cloud_control(self) -> list[CloudAsset]:
        if not self._cloud_control:
            return []
        types = self._cc_selected(await self._cc_listable_types())
        skipped: dict[str, str] = {}

        async with self._client("cloudcontrol") as cc:

            async def list_type(type_name: str) -> list[CloudAsset]:
                out: list[CloudAsset] = []
                try:
                    async for desc in self._paginate(cc, "list_resources", "ResourceDescriptions", TypeName=type_name):
                        out.append(self._cc_asset(type_name, desc))
                        if len(out) >= _MAX_RESOURCES_PER_TYPE:
                            logger.warning("Cloud Control: %s truncated at %d", type_name, len(out))
                            break
                except Exception as exc:
                    skipped[type_name] = error_code(exc)
                return out

            results = await gather_limited(
                [lambda t=t: list_type(t) for t in types], limit=self._cloud_control_concurrency
            )

        assets = [a for batch in results if batch for a in batch]
        if skipped:
            codes: dict[str, int] = {}
            for code in skipped.values():
                codes[code] = codes.get(code, 0) + 1
            self.coverage.record(
                "cloud_control_skipped_types",
                ServiceStatus.PARTIAL,
                asset_count=len(skipped),
                error=", ".join(f"{c}: {n}" for c, n in sorted(codes.items())),
            )
            logger.debug("Cloud Control skipped types: %s", skipped)
        logger.info(
            "Cloud Control (%s): %d resources across %d types",
            self._region,
            len(assets),
            len(types) - len(skipped),
        )
        return assets

    def _cloudcontrol_tasks(self) -> dict[str, tuple[Any, str, bool]]:
        if not self._cloud_control:
            return {}
        return {"cloud_control": (self._collect_cloud_control, "sweep", False)}
