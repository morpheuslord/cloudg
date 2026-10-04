"""Threat detection and scanning: GuardDuty, Security Hub, Inspector2,
Macie and Detective."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.security._common import (
    SecurityServiceMixin,
    _administrator_rel,
    _disabled_reason,
    _not_enabled,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

_MAX_COVERAGE = 10000
# Security Hub product integrations -> the security alias they ingest from.
_HUB_SOURCES = ("guardduty", "inspector", "macie", "access-analyzer", "config")
_HUB_ALIAS = {"inspector": "inspector2", "access-analyzer": "accessanalyzer"}


def _coverage_target(resource_id: str) -> str:
    """Inspector reports ECR images as repo/sha256 ARNs: link to the repository."""
    if ":repository/" in resource_id and "/sha256:" in resource_id:
        return resource_id.split("/sha256:", 1)[0]
    return resource_id


def _coverage_rel(res: dict, status: str) -> dict[str, Any] | None:
    return rel(
        _coverage_target(res.get("resourceId", "")),
        EdgeType.MONITORS,
        "MONITORED_BY",
        description=f"{res.get('scanType')} scan",
        scan_status=status,
        reason=(res.get("scanStatus") or {}).get("reason"),
        resource_type=res.get("resourceType"),
    )


def _inspector_resource_state(acct: dict) -> tuple[dict[str, Any], bool]:
    """Per resource type scan status, and whether any scanning is enabled."""
    resource_state = {
        k: (v or {}).get("status") for k, v in (acct.get("resourceState") or {}).items()
    }
    enabled = (acct.get("state") or {}).get("status") == "ENABLED" or any(
        s == "ENABLED" for s in resource_state.values()
    )
    return resource_state, enabled


class DetectionCollectorsMixin(SecurityServiceMixin):
    async def _collect_guardduty(self) -> list[CloudAsset]:
        async with self._client("guardduty") as gd:
            ids = [d async for d in self._paginate(gd, "list_detectors", "DetectorIds")]
            if not ids:
                return [self._disabled_asset("guardduty", AssetType.THREAT_DETECTOR, "GuardDuty")]
            return [await self._guardduty_detector_asset(gd, det_id) for det_id in ids]

    async def _guardduty_detector_asset(self, gd: Any, det_id: str) -> CloudAsset:
        d = await gd.get_detector(DetectorId=det_id)
        admin = None
        try:
            admin = (
                (await gd.get_administrator_account(DetectorId=det_id)).get("Administrator") or {}
            ).get("AccountId")
        except Exception as exc:
            logger.debug("GuardDuty admin lookup failed: %s", exc)
        features = {f.get("Name"): f.get("Status") for f in d.get("Features", []) or []}
        return self._asset(
            arn=self._arn("guardduty", f"detector/{det_id}"),
            name=f"guardduty-{det_id[:8]}",
            asset_type=AssetType.THREAT_DETECTOR,
            tags=d.get("Tags"),
            metadata={
                "security_service": "guardduty",
                "enabled": d.get("Status") == "ENABLED",
                "status": d.get("Status"),
                "features": features,
                "finding_frequency": d.get("FindingPublishingFrequency"),
                "administrator_account": admin,
            },
            relations=[
                self._monitors_account("threat detection"),
                _administrator_rel(admin, "GuardDuty administrator"),
            ],
            aliases=[self._security_alias("guardduty")],
        )

    async def _collect_securityhub(self) -> list[CloudAsset]:
        async with self._client("securityhub") as sh:
            try:
                hub = await sh.describe_hub()
            except Exception as exc:
                if _not_enabled(exc):
                    return [
                        self._disabled_asset(
                            "securityhub",
                            AssetType.SECURITY_HUB,
                            "Security Hub",
                            _disabled_reason(exc),
                        )
                    ]
                raise
            standards = [
                s.get("StandardsArn", "").split("/standards/", 1)[-1]
                for s in await self._security_listing(
                    sh,
                    "get_enabled_standards",
                    "StandardsSubscriptions",
                    "Security Hub standards unavailable: %s",
                )
            ]
            products = await self._security_listing(
                sh,
                "list_enabled_products_for_import",
                "ProductSubscriptions",
                "Security Hub products unavailable: %s",
            )
            admin = None
            try:
                admin = ((await sh.get_administrator_account()).get("Administrator") or {}).get(
                    "AccountId"
                )
            except Exception as exc:
                logger.debug("Security Hub admin lookup failed: %s", exc)
            integrations = sorted({p.rsplit("/", 1)[-1] for p in products})
            return [self._securityhub_asset(hub, standards, integrations, admin)]

    def _securityhub_asset(
        self, hub: dict, standards: list[str], integrations: list[str], admin: str | None
    ) -> CloudAsset:
        relations = [
            self._monitors_account("posture management"),
            _administrator_rel(admin, "Security Hub administrator"),
        ]
        for svc in _HUB_SOURCES:
            if svc in integrations or svc.replace("-", "") in integrations:
                relations.append(
                    rel(
                        self._security_alias(_HUB_ALIAS.get(svc, svc)),
                        EdgeType.MONITORS,
                        "READS_FROM",
                        description=f"ingests {svc} findings",
                    )
                )
        return self._asset(
            arn=hub.get("HubArn", self._arn("securityhub", "hub/default")),
            name="security-hub",
            asset_type=AssetType.SECURITY_HUB,
            metadata={
                "security_service": "securityhub",
                "enabled": True,
                "subscribed_at": hub.get("SubscribedAt"),
                "auto_enable_controls": hub.get("AutoEnableControls"),
                "standards": standards,
                "integrations": integrations,
                "administrator_account": admin,
            },
            relations=relations,
            aliases=[self._security_alias("securityhub")],
        )

    async def _collect_inspector2(self) -> list[CloudAsset]:
        async with self._client("inspector2") as insp:
            resp = await insp.batch_get_account_status(
                accountIds=[self._account_id] if self._account_id else []
            )
            accounts = resp.get("accounts", [])
            resource_state, enabled = (
                _inspector_resource_state(accounts[0]) if accounts else ({}, False)
            )
            if not enabled:
                return [
                    self._disabled_asset("inspector2", AssetType.VULNERABILITY_SCANNER, "Inspector")
                ]
            relations, status_counts, covered = await self._inspector_coverage(insp)
            return [
                self._asset(
                    arn=self._arn("inspector2", "scanner"),
                    name="inspector",
                    asset_type=AssetType.VULNERABILITY_SCANNER,
                    metadata={
                        "security_service": "inspector2",
                        "enabled": True,
                        "resource_types": resource_state,
                        "covered_resources": covered,
                        "scan_status_counts": status_counts,
                    },
                    relations=relations,
                    aliases=[self._security_alias("inspector2")],
                )
            ]

    async def _inspector_coverage(self, insp: Any) -> tuple[list[dict | None], dict[str, int], int]:
        """MONITORS relations to every covered resource, with scan status counts."""
        relations: list[dict | None] = []
        status_counts: dict[str, int] = {}
        covered = 0
        try:
            async for res in self._paginate(insp, "list_coverage", "coveredResources"):
                covered += 1
                if covered > _MAX_COVERAGE:
                    logger.warning("Inspector coverage truncated at %d resources", _MAX_COVERAGE)
                    break
                status = (res.get("scanStatus") or {}).get("statusCode", "UNKNOWN")
                status_counts[status] = status_counts.get(status, 0) + 1
                relations.append(_coverage_rel(res, status))
        except Exception as exc:
            logger.debug("Inspector coverage listing failed: %s", exc)
        return relations, status_counts, covered

    async def _collect_macie(self) -> list[CloudAsset]:
        async with self._client("macie2") as macie:
            try:
                session = await macie.get_macie_session()
            except Exception as exc:
                if _not_enabled(exc):
                    return [
                        self._disabled_asset(
                            "macie", AssetType.DATA_SECURITY_SCANNER, "Macie", _disabled_reason(exc)
                        )
                    ]
                raise
            enabled = session.get("status") == "ENABLED"
            if not enabled:
                return [
                    self._disabled_asset(
                        "macie", AssetType.DATA_SECURITY_SCANNER, "Macie", "paused"
                    )
                ]
            return [
                self._asset(
                    arn=self._arn("macie2", "session"),
                    name="macie",
                    asset_type=AssetType.DATA_SECURITY_SCANNER,
                    metadata={
                        "security_service": "macie",
                        "enabled": True,
                        "finding_frequency": session.get("findingPublishingFrequency"),
                        "service_role": session.get("serviceRole"),
                    },
                    relations=[
                        self._monitors_account("sensitive data discovery"),
                        rel(session.get("serviceRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                    ],
                    aliases=[self._security_alias("macie")],
                )
            ]

    async def _collect_detective(self) -> list[CloudAsset]:
        async with self._client("detective") as det:
            graphs = (await det.list_graphs()).get("GraphList", [])
            return [
                self._asset(
                    arn=g["Arn"],
                    name="detective",
                    asset_type=AssetType.THREAT_DETECTOR,
                    metadata={"security_service": "detective", "enabled": True},
                    relations=[self._monitors_account("investigation graph")],
                    aliases=[self._security_alias("detective")],
                )
                for g in graphs
            ]
