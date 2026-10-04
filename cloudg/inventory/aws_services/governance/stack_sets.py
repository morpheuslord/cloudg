"""CloudFormation StackSets: MANAGES every stack instance and target account."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
from cloudg.inventory.aws_services.governance._common import (
    _MAX_POLICY_REFS,
    _MAX_STACK_INSTANCES,
    _root,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _instance_relations(instances: list[dict]) -> tuple[list[dict | None], dict[str, int]]:
    """MANAGES relations to every stack instance, plus counts by status."""
    status_counts: dict[str, int] = {}
    relations: list[dict | None] = []
    for inst in instances:
        status = inst.get("Status") or "UNKNOWN"
        status_counts[status] = status_counts.get(status, 0) + 1
        relations.append(
            rel(
                inst.get("StackId"),
                EdgeType.MANAGES,
                "OWNED_BY",
                description="stack instance",
                account=inst.get("Account"),
                region=inst.get("Region"),
                status=status,
                drift_status=inst.get("DriftStatus"),
            )
        )
    return relations, status_counts


def _target_relations(
    ss: dict[str, Any], summary: dict[str, Any], accounts: list[str]
) -> list[dict | None]:
    """Target accounts, deployment OUs and (self-managed) execution roles."""
    relations: list[dict | None] = [
        rel(_root(acct), EdgeType.MANAGES, "OWNED_BY", description="stack set target account")
        for acct in accounts
    ]
    relations += [
        rel(ou, EdgeType.REFERENCES, "DEPENDS_ON", description="deployment target OU")
        for ou in ss.get("OrganizationalUnitIds") or []
    ]
    exec_role = ss.get("ExecutionRoleName")
    if (
        exec_role
        and (ss.get("PermissionModel") or summary.get("PermissionModel")) == "SELF_MANAGED"
    ):
        relations += [
            rel(
                f"arn:aws:iam::{acct}:role/{exec_role}",
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="stack set execution role",
            )
            for acct in accounts[:_MAX_POLICY_REFS]
        ]
    return relations


class StackSetsCollectorsMixin(AWSServiceMixin):
    """CloudFormation StackSets collector."""

    async def _stack_set_instances(
        self, cfn: Any, name: str, call_as: str
    ) -> tuple[dict[str, Any], list[dict]]:
        """Stack set description and its (capped) stack instances."""
        ss: dict[str, Any] = {}
        try:
            ss = (await cfn.describe_stack_set(StackSetName=name, CallAs=call_as)).get(
                "StackSet"
            ) or {}
        except Exception as exc:
            logger.debug("Stack set %s describe failed: %s", name, exc)
        instances: list[dict] = []
        try:
            async for inst in self._paginate(
                cfn, "list_stack_instances", "Summaries", StackSetName=name, CallAs=call_as
            ):
                instances.append(inst)
                if len(instances) >= _MAX_STACK_INSTANCES:
                    logger.warning("Stack set %s: instances truncated", name)
                    break
        except Exception as exc:
            logger.debug("Stack set %s instances failed: %s", name, exc)
        return ss, instances

    async def _stack_set_asset(self, cfn: Any, summary: dict[str, Any], call_as: str) -> CloudAsset:
        name = summary["StackSetName"]
        ss, instances = await self._stack_set_instances(cfn, name, call_as)
        accounts = sorted({i.get("Account") for i in instances if i.get("Account")})
        regions = sorted(
            {i.get("Region") for i in instances if i.get("Region")} | set(ss.get("Regions") or [])
        )
        instance_rels, status_counts = _instance_relations(instances)
        relations: list[dict | None] = [
            rel(
                ss.get("AdministrationRoleARN"),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="stack set administration role",
            ),
            *instance_rels,
            *_target_relations(ss, summary, accounts),
        ]
        drift = ss.get("StackSetDriftDetectionDetails") or {}
        auto = ss.get("AutoDeployment") or summary.get("AutoDeployment") or {}
        stack_set_id = ss.get("StackSetId") or summary.get("StackSetId") or name
        return self._asset(
            arn=ss.get("StackSetARN") or self._arn("cloudformation", f"stackset/{stack_set_id}"),
            name=name,
            asset_type=AssetType.STACK_SET,
            tags=ss.get("Tags"),
            metadata={
                "stack_set_id": stack_set_id,
                "status": ss.get("Status") or summary.get("Status"),
                "description": ss.get("Description") or summary.get("Description"),
                "permission_model": ss.get("PermissionModel") or summary.get("PermissionModel"),
                "call_as": call_as,
                "auto_deployment": bool(auto.get("Enabled")),
                "retain_on_account_removal": auto.get("RetainStacksOnAccountRemoval"),
                "capabilities": ss.get("Capabilities") or [],
                "administration_role": ss.get("AdministrationRoleARN"),
                "execution_role_name": ss.get("ExecutionRoleName"),
                "organizational_unit_ids": ss.get("OrganizationalUnitIds") or [],
                "regions": regions,
                "accounts": accounts,
                "instance_count": len(instances),
                "instance_status": status_counts,
                "drift_status": drift.get("DriftStatus") or summary.get("DriftStatus"),
                "control_tower": name.startswith("AWSControlTower"),
            },
            relations=relations,
            aliases=[stack_set_id],
        )

    async def _collect_stack_sets(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        seen: set[str] = set()
        errors: list[BaseException] = []
        async with self._client("cloudformation") as cfn:
            for call_as in ("SELF", "DELEGATED_ADMIN"):
                try:
                    summaries = [
                        s
                        async for s in self._paginate(
                            cfn, "list_stack_sets", "Summaries", Status="ACTIVE", CallAs=call_as
                        )
                    ]
                except Exception as exc:
                    # DELEGATED_ADMIN fails with ValidationError outside a
                    # delegated administrator account
                    logger.debug("StackSets as %s unavailable: %s", call_as, exc)
                    errors.append(exc)
                    continue
                todo = [
                    s
                    for s in summaries
                    if s.get("StackSetId") not in seen and s.get("StackSetName")
                ]
                seen.update(s.get("StackSetId") for s in todo)
                results = await gather_limited(
                    [lambda s=s, c=call_as: self._stack_set_asset(cfn, s, c) for s in todo], limit=4
                )
                assets.extend(a for a in results if a)
        if len(errors) == 2:
            raise errors[0]
        return assets
