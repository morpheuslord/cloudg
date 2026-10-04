"""Lake Formation: data lake admins, registered locations and catalog /
location grants."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import as_list, principal_ref, rel
from cloudg.inventory.aws_services.data_ml._common import (
    _MAX_LF_PERMISSIONS,
    DataMLHelpersMixin,
    Relations,
    _bucket_arn,
    _linkable_principal,
    _permission_grant_rels,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _principals(entries: Any) -> list[str]:
    ids = [(e or {}).get("DataLakePrincipalIdentifier") for e in as_list(entries)]
    return [principal_ref(i) for i in ids if _linkable_principal(i)]


def _admin_rels(admins: list[str], readonly: list[str]) -> Relations:
    return [
        rel(p, EdgeType.GRANTS_ACCESS, "POLICY_ALLOWS_ACTION", reverse=True, description=desc)
        for principals, desc in (
            (admins, "data lake administrator"),
            (readonly, "read-only data lake administrator"),
        )
        for p in principals
    ]


def _location_rels(resources: list[dict]) -> tuple[list[Any], Relations]:
    """(registered location ARNs, GOVERNS + registration role relations)."""
    locations = []
    relations: Relations = []
    for r in resources:
        arn = r.get("ResourceArn")
        locations.append(arn)
        relations.append(
            rel(
                _bucket_arn(arn) or arn,
                EdgeType.GOVERNS,
                "COMPLIANCE_GOVERNS",
                description="registered data location",
            )
        )
        relations.append(
            rel(
                r.get("RoleArn"),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="location registration role",
            )
        )
    return locations, relations


def _catalog_grants(permissions: list[dict]) -> tuple[dict[str, set[str]], list[dict[str, Any]]]:
    """(principal -> catalog / location permissions, data location grants)."""
    grants: dict[str, set[str]] = {}
    location_grants: list[dict[str, Any]] = []
    for p in permissions:
        res = p.get("Resource") or {}
        if not (res.get("Catalog") is not None or res.get("DataLocation")):
            continue
        principal = (p.get("Principal") or {}).get("DataLakePrincipalIdentifier")
        if not _linkable_principal(principal):
            continue
        grants.setdefault(principal_ref(principal), set()).update(p.get("Permissions") or [])
        if res.get("DataLocation"):
            location_grants.append(
                {
                    "principal": principal,
                    "location": res["DataLocation"].get("ResourceArn"),
                    "permissions": p.get("Permissions") or [],
                }
            )
    return grants, location_grants


class LakeFormationCollectorsMixin(DataMLHelpersMixin):
    """Lake Formation data lake settings collector."""

    async def _lf_state(self) -> tuple[dict, list[dict], list[dict]]:
        """(data lake settings, registered resources, permissions)."""
        async with self._client("lakeformation") as lf:
            settings = (await lf.get_data_lake_settings()).get("DataLakeSettings") or {}
            resources: list[dict] = []
            try:
                resources = [r async for r in self._pages(lf.list_resources, "ResourceInfoList")]
            except Exception as exc:
                logger.debug("Lake Formation resource listing failed: %s", exc)
            permissions: list[dict] = []
            try:
                permissions = await self._lf_permissions(lf)
            except Exception as exc:
                logger.debug("Lake Formation permission listing failed: %s", exc)
        return settings, resources, permissions

    async def _collect_lakeformation(self) -> list[CloudAsset]:
        settings, resources, permissions = await self._lf_state()
        relations: Relations = [
            rel(self._arn("glue", "catalog"), EdgeType.GOVERNS, "COMPLIANCE_GOVERNS"),
        ]
        admins = _principals(settings.get("DataLakeAdmins"))
        readonly = _principals(settings.get("ReadOnlyAdmins"))
        relations += _admin_rels(admins, readonly)
        locations, location_rels = _location_rels(resources)
        relations += location_rels
        grants, location_grants = _catalog_grants(permissions)
        relations += _permission_grant_rels(grants, "Lake Formation catalog / location grant")
        defaults = (settings.get("CreateDatabaseDefaultPermissions") or []) + (
            settings.get("CreateTableDefaultPermissions") or []
        )
        return [
            self._asset(
                arn=f"cloudg:aws:lakeformation:{self._region}:{self._account_id}:data-lake",
                name=f"Lake Formation data lake ({self._region})",
                asset_type=AssetType.DATA_CATALOG,
                metadata={
                    "service": "lakeformation",
                    "kind": "data_lake_settings",
                    "admins": admins,
                    "read_only_admins": readonly,
                    "registered_locations": locations,
                    "iam_allowed_principals_default": any(
                        (d.get("Principal") or {}).get("DataLakePrincipalIdentifier")
                        == "IAM_ALLOWED_PRINCIPALS"
                        for d in defaults
                    ),
                    "trusted_resource_owners": settings.get("TrustedResourceOwners") or [],
                    "external_data_filtering": settings.get("AllowExternalDataFiltering"),
                    "permission_count": len(permissions),
                    "permissions_capped": len(permissions) >= _MAX_LF_PERMISSIONS,
                    "data_location_grants": location_grants[:100],
                },
                relations=relations,
            )
        ]
