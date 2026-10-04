"""Glue Data Catalog: catalog encryption, databases (Lake Formation grants)
and the security configurations shared by jobs and crawlers."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import gather_limited, principal_ref, rel
from cloudg.inventory.aws_services.data_ml._common import (
    _MAX_TABLES_COUNTED,
    Relations,
    _bucket_arn,
    _kms_ref,
    _linkable_principal,
    _permission_grant_rels,
    logger,
)
from cloudg.inventory.aws_services.data_ml.glue_etl import GlueEtlCollectorsMixin
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

DatabaseGrants = dict[str, dict[str, set[str]]]


def _security_keys(sc: dict) -> list[str]:
    """KMS keys of a Glue security configuration."""
    enc = sc.get("EncryptionConfiguration") or {}
    keys = [s.get("KmsKeyArn") for s in enc.get("S3Encryption") or []]
    for block in ("CloudWatchEncryption", "JobBookmarksEncryption", "DataQualityEncryption"):
        keys.append((enc.get(block) or {}).get("KmsKeyArn"))
    return sorted({k for k in keys if _kms_ref(k)})


def _permission_database(p: dict) -> Any:
    res = p.get("Resource") or {}
    return (
        (res.get("Database") or {}).get("Name")
        or (res.get("Table") or {}).get("DatabaseName")
        or (res.get("TableWithColumns") or {}).get("DatabaseName")
    )


class GlueCollectorsMixin(GlueEtlCollectorsMixin):
    """Glue Data Catalog collectors (jobs and crawlers via the ETL mixin)."""

    async def _glue_security_keys(self, glue: Any) -> dict[str, list[str]]:
        security_keys: dict[str, list[str]] = {}
        try:
            async for sc in self._paginate(
                glue, "get_security_configurations", "SecurityConfigurations"
            ):
                security_keys[sc["Name"]] = _security_keys(sc)
        except Exception as exc:
            logger.debug("Glue security configuration listing failed: %s", exc)
        return security_keys

    async def _collect_glue(self) -> list[CloudAsset]:
        async with self._client("glue") as glue:
            security_keys = await self._glue_security_keys(glue)

            def security_rels(name: Any) -> list[dict[str, Any] | None]:
                return [
                    rel(k, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS", security_configuration=name)
                    for k in security_keys.get(name, [])
                    if isinstance(name, str)
                ]

            return await self._gather_parts(
                "glue",
                {
                    "catalog": lambda: self._glue_databases(glue),
                    "jobs": lambda: self._glue_jobs(glue, security_rels),
                    "crawlers": lambda: self._glue_crawlers(glue, security_rels),
                    "connections": lambda: self._glue_connections(glue),
                    "triggers": lambda: self._glue_triggers(glue),
                },
            )

    # ------------------------------------------------------------------
    # Databases + catalog
    # ------------------------------------------------------------------

    async def _lf_database_grants(self) -> DatabaseGrants:
        """database -> principal -> Lake Formation permissions."""
        grants: DatabaseGrants = {}
        try:
            async with self._client("lakeformation") as lf:
                for p in await self._lf_permissions(lf):
                    db = _permission_database(p)
                    principal = (p.get("Principal") or {}).get("DataLakePrincipalIdentifier")
                    if not db or not _linkable_principal(principal):
                        continue
                    grants.setdefault(db, {}).setdefault(principal_ref(principal), set()).update(
                        p.get("Permissions") or []
                    )
        except Exception as exc:
            logger.debug("Lake Formation permission listing failed: %s", exc)
        return grants

    async def _glue_table_count(self, glue: Any, name: str) -> int | None:
        count = 0
        try:
            async for _ in self._paginate(glue, "get_tables", "TableList", DatabaseName=name):
                count += 1
                if count >= _MAX_TABLES_COUNTED:
                    break
        except Exception as exc:
            logger.debug("Glue table listing failed for %s: %s", name, exc)
            return None
        return count

    async def _glue_databases(self, glue: Any) -> list[CloudAsset]:
        databases = [d async for d in self._paginate(glue, "get_databases", "DatabaseList")]
        catalog_arn = self._arn("glue", "catalog")
        grants = await self._lf_database_grants()
        counts = await gather_limited(
            [lambda n=d["Name"]: self._glue_table_count(glue, n) for d in databases]
        )
        assets = [
            self._glue_database(d, tables, catalog_arn, grants.get(d["Name"], {}))
            for d, tables in zip(databases, counts)
        ]
        assets.append(await self._glue_catalog(glue, catalog_arn, len(databases)))
        return assets

    def _glue_database_rels(self, d: dict, catalog_arn: str) -> Relations:
        target = d.get("TargetDatabase") or {}
        relations: Relations = [
            rel(catalog_arn, EdgeType.CONTAINS, reverse=True),
            rel(
                _bucket_arn(d.get("LocationUri")),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="database location",
            ),
        ]
        if target.get("DatabaseName"):
            relations.append(
                rel(
                    f"arn:aws:glue:{target.get('Region') or self._region}:{target.get('CatalogId') or self._account_id}"
                    f":database/{target['DatabaseName']}",
                    EdgeType.REFERENCES,
                    "DEPENDS_ON",
                    description="resource link",
                )
            )
        return relations

    def _glue_database(
        self, d: dict, tables: int | None, catalog_arn: str, grants: dict[str, set[str]]
    ) -> CloudAsset:
        name = d["Name"]
        relations = self._glue_database_rels(d, catalog_arn)
        relations += _permission_grant_rels(grants, "Lake Formation grant")
        return self._asset(
            arn=self._glue_arn("database", name),
            name=name,
            asset_type=AssetType.DATA_CATALOG,
            metadata={
                "service": "glue",
                "kind": "database",
                "location": d.get("LocationUri"),
                "table_count": tables,
                "table_count_capped": tables is not None and tables >= _MAX_TABLES_COUNTED,
                "resource_link": bool(d.get("TargetDatabase") or {}),
                "federated": (d.get("FederatedDatabase") or {}).get("ConnectionName"),
                "iam_allowed_principals_default": any(
                    (p.get("Principal") or {}).get("DataLakePrincipalIdentifier")
                    == "IAM_ALLOWED_PRINCIPALS"
                    for p in d.get("CreateTableDefaultPermissions") or []
                ),
            },
            relations=relations,
        )

    async def _glue_catalog(self, glue: Any, catalog_arn: str, database_count: int) -> CloudAsset:
        kms: str | None = None
        encryption: dict = {}
        try:
            encryption = (await glue.get_data_catalog_encryption_settings()).get(
                "DataCatalogEncryptionSettings"
            ) or {}
            kms = _kms_ref((encryption.get("EncryptionAtRest") or {}).get("SseAwsKmsKeyId"))
        except Exception as exc:
            logger.debug("Glue catalog encryption lookup failed: %s", exc)
        pw = encryption.get("ConnectionPasswordEncryption") or {}
        pw_kms = _kms_ref(pw.get("AwsKmsKeyId"))
        return self._asset(
            arn=catalog_arn,
            name=f"Glue Data Catalog ({self._region})",
            asset_type=AssetType.DATA_CATALOG,
            metadata={
                "service": "glue",
                "kind": "catalog",
                "database_count": database_count,
                "encryption_mode": (encryption.get("EncryptionAtRest") or {}).get(
                    "CatalogEncryptionMode"
                ),
                "kms_key_id": kms,
                "connection_password_encryption": pw.get("ReturnConnectionPasswordEncrypted"),
            },
            relations=[
                rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                rel(pw_kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            ],
        )
