"""AWS Backup: plans, rules, copy actions, selections, vaults (KMS, access
policy, lock), protected resources."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import error_code, gather_limited, rel
from cloudg.inventory.aws_services.application._common import (
    _MAX_PROTECTED_RESOURCES,
    ApplicationBase,
    _role_rel,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


class BackupCollectorsMixin(ApplicationBase):
    """AWS Backup plan and vault collectors."""

    def _vault_ref(self, name: Any) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        return name if name.startswith("arn:") else self._arn("backup", f"backup-vault:{name}")

    def _backup_copy_action(self, c: dict, rule_name: Any, relations: list) -> dict[str, Any]:
        dest = c.get("DestinationBackupVaultArn")
        cross_acct = self._cross_account(dest)
        cross_region = bool(dest and dest.split(":")[3:4] != [self._region])
        relations.append(
            rel(
                dest,
                EdgeType.REFERENCES,
                "BACKUP_TO",
                description=f"rule {rule_name} copy action",
                cross_account=cross_acct or None,
                cross_region=cross_region or None,
            )
        )
        return {"destination": dest, "cross_account": cross_acct, "cross_region": cross_region}

    def _backup_rule(self, r: dict, relations: list) -> dict[str, Any]:
        """One plan rule's summary; its vault / copy relations go into ``relations``."""
        vault = r.get("TargetBackupVaultName")
        relations.append(
            rel(
                self._vault_ref(vault),
                EdgeType.REFERENCES,
                "BACKUP_TO",
                description=f"rule {r.get('RuleName')} target vault",
            )
        )
        copies = [
            self._backup_copy_action(c, r.get("RuleName"), relations)
            for c in r.get("CopyActions", []) or []
        ]
        lifecycle = r.get("Lifecycle") or {}
        return {
            "name": r.get("RuleName"),
            "vault": vault,
            "schedule": r.get("ScheduleExpression"),
            "continuous": r.get("EnableContinuousBackup", False),
            "delete_after_days": lifecycle.get("DeleteAfterDays"),
            "cold_storage_after_days": lifecycle.get("MoveToColdStorageAfterDays"),
            "copy_actions": copies,
        }

    async def _backup_selection(
        self, bk: Any, pid: str, s: dict, relations: list
    ) -> dict[str, Any]:
        """One selection's summary; its role / resource relations go into ``relations``."""
        sel_meta: dict[str, Any] = {
            "name": s.get("SelectionName"),
            "iam_role": s.get("IamRoleArn"),
        }
        relations.append(_role_rel(s.get("IamRoleArn"), "backup selection role"))
        try:
            full = (
                await bk.get_backup_selection(BackupPlanId=pid, SelectionId=s["SelectionId"])
            ).get("BackupSelection") or {}
        except Exception as exc:
            logger.debug("get_backup_selection failed for %s: %s", s.get("SelectionId"), exc)
            full = {}
        resources = full.get("Resources", []) or []
        sel_meta["resources"] = resources[:200]
        sel_meta["not_resources"] = (full.get("NotResources", []) or [])[:200]
        sel_meta["tag_conditions"] = [
            {
                "type": t.get("ConditionType"),
                "key": t.get("ConditionKey"),
                "value": t.get("ConditionValue"),
            }
            for t in full.get("ListOfTags", []) or []
        ]
        sel_meta["conditions"] = full.get("Conditions") or {}
        relations.extend(
            rel(
                res,
                EdgeType.MANAGES,
                "BACKUP_TO",
                description=f"selection {s.get('SelectionName')}",
            )
            for res in resources
            if "*" not in res
        )
        return sel_meta

    async def _backup_selections(self, bk: Any, pid: str, relations: list) -> list[dict]:
        selections: list[dict] = []
        try:
            async for s in self._paginate(
                bk, "list_backup_selections", "BackupSelectionsList", BackupPlanId=pid
            ):
                selections.append(await self._backup_selection(bk, pid, s, relations))
        except Exception as exc:
            logger.debug("Backup selections failed for %s: %s", pid, exc)
        return selections

    async def _backup_plan_asset(self, bk: Any, summary: dict) -> CloudAsset:
        pid = summary["BackupPlanId"]
        resp = await bk.get_backup_plan(BackupPlanId=pid)
        plan = resp.get("BackupPlan") or {}
        relations: list[dict | None] = []
        rules = [self._backup_rule(r, relations) for r in plan.get("Rules", []) or []]
        selections = await self._backup_selections(bk, pid, relations)
        return self._asset(
            arn=resp.get("BackupPlanArn")
            or summary.get("BackupPlanArn")
            or self._arn("backup", f"backup-plan:{pid}"),
            name=plan.get("BackupPlanName") or summary.get("BackupPlanName") or pid,
            asset_type=AssetType.BACKUP_PLAN,
            metadata={
                "service": "backup",
                "plan_id": pid,
                "version_id": resp.get("VersionId"),
                "rules": rules,
                "selections": selections,
                "last_execution": str(summary.get("LastExecutionDate") or "") or None,
                "advanced_settings": [
                    a.get("ResourceType") for a in plan.get("AdvancedBackupSettings", []) or []
                ],
            },
            relations=relations,
            aliases=[pid],
        )

    async def _collect_backup_plans(self) -> list[CloudAsset]:
        async with self._client("backup") as bk:
            plans = [p async for p in self._paginate(bk, "list_backup_plans", "BackupPlansList")]
            results = await gather_limited(
                [lambda p=p: self._backup_plan_asset(bk, p) for p in plans]
            )
        return [a for a in results if a]

    async def _backup_protected_resources(self, bk: Any) -> dict[str, list[dict]]:
        """Protected resources keyed by the vault they were last backed up to."""
        protected: dict[str, list[dict]] = {}
        try:
            count = 0
            async for r in self._paginate(bk, "list_protected_resources", "Results"):
                count += 1
                if count > _MAX_PROTECTED_RESOURCES:
                    break
                protected.setdefault(r.get("LastBackupVaultArn") or "", []).append(r)
        except Exception as exc:
            logger.debug("list_protected_resources failed: %s", exc)
        return protected

    async def _backup_vault_policy(
        self, bk: Any, name: str
    ) -> tuple[list[dict | None], bool, bool]:
        """Access-policy grants, whether a policy exists, and public access."""
        relations: list[dict | None] = []
        public = has_policy = False
        try:
            pol = await bk.get_backup_vault_access_policy(BackupVaultName=name)
            has_policy = bool(pol.get("Policy"))
            relations, public = self._app_policy_grants(pol.get("Policy"), "vault access policy")
        except Exception as exc:
            if error_code(exc) not in ("ResourceNotFoundException",):
                logger.debug("Vault policy read failed for %s: %s", name, exc)
        return relations, has_policy, public

    async def _backup_vault_asset(self, bk: Any, v: dict, prot: list[dict]) -> CloudAsset:
        name, arn = v.get("BackupVaultName", ""), v.get("BackupVaultArn", "")
        relations: list[dict | None] = [
            rel(v.get("EncryptionKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        ]
        grants, has_policy, public = await self._backup_vault_policy(bk, name)
        relations += grants
        relations.extend(
            rel(
                r.get("ResourceArn"),
                EdgeType.REFERENCES,
                "BACKUP_TO",
                reverse=True,
                description="protected resource last backed up here",
            )
            for r in prot
        )
        return self._asset(
            arn=arn,
            name=name,
            asset_type=AssetType.BACKUP_VAULT,
            metadata={
                "service": "backup",
                "vault_type": v.get("VaultType"),
                "state": v.get("VaultState"),
                "kms_key_id": v.get("EncryptionKeyArn"),
                "recovery_points": v.get("NumberOfRecoveryPoints"),
                "locked": v.get("Locked", False),
                "min_retention_days": v.get("MinRetentionDays"),
                "max_retention_days": v.get("MaxRetentionDays"),
                "lock_date": str(v.get("LockDate") or "") or None,
                "has_access_policy": has_policy,
                "policy_allows_public": public,
                "protected_resources": len(prot),
                "protected_resource_types": sorted({r.get("ResourceType", "") for r in prot}),
            },
            relations=relations,
            exposed=public,
            aliases=[self._vault_ref(name) if self._vault_ref(name) != arn else None],
        )

    async def _collect_backup_vaults(self) -> list[CloudAsset]:
        async with self._client("backup") as bk:
            vaults = [v async for v in self._paginate(bk, "list_backup_vaults", "BackupVaultList")]
            protected = await self._backup_protected_resources(bk)
            results = await gather_limited(
                [
                    lambda v=v: self._backup_vault_asset(
                        bk, v, protected.get(v.get("BackupVaultArn", ""), [])
                    )
                    for v in vaults
                ]
            )
        return [a for a in results if a]
