"""Systems Manager: parameter *metadata* (never values), managed instances
and hybrid nodes, self-owned documents and their shares, associations,
maintenance windows."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import gather_limited, principal_ref, rel
from cloudg.inventory.aws_services.application._common import (
    _MAX_PARAMETERS,
    ApplicationBase,
    _bucket_arn,
    _is_aws_owned_document,
    _role_rel,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


class OperationsCollectorsMixin(ApplicationBase):
    """Systems Manager collectors."""

    def _ssm_parameter_asset(self, p: dict) -> CloudAsset:
        name = p.get("Name", "")
        arn = p.get("ARN") or self._param_arn(name)
        key = p.get("KeyId")
        return self._asset(
            arn=arn,
            name=name,
            asset_type=AssetType.PARAMETER,
            metadata={
                "service": "ssm",
                "type": p.get("Type"),
                "tier": p.get("Tier"),
                "data_type": p.get("DataType"),
                "version": p.get("Version"),
                "kms_key_id": key,
                "last_modified": str(p.get("LastModifiedDate") or "") or None,
                "last_modified_user": p.get("LastModifiedUser"),
                "description": p.get("Description"),
                "has_policies": bool(p.get("Policies")),
                "secure": p.get("Type") == "SecureString",
            },
            relations=[rel(key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")] if key else [],
            aliases=[self._param_arn(name)] if self._param_arn(name) != arn else [],
        )

    async def _collect_ssm_parameters(self) -> list[CloudAsset]:
        """Parameter metadata only: get_parameter(s) is never called."""
        assets: list[CloudAsset] = []
        async with self._client("ssm") as ssm:
            async for p in self._paginate(
                ssm,
                "describe_parameters",
                "Parameters",
                PaginationConfig={"MaxItems": _MAX_PARAMETERS},
            ):
                if len(assets) >= _MAX_PARAMETERS:
                    break
                assets.append(self._ssm_parameter_asset(p))
        return assets

    def _ssm_hybrid_node_asset(self, info: dict, arn: str) -> CloudAsset:
        iid = info.get("InstanceId", "")
        return self._asset(
            arn=arn,
            name=info.get("Name") or info.get("ComputerName") or iid,
            asset_type=AssetType.VIRTUAL_MACHINE,
            metadata={
                "service": "ssm",
                "hybrid": True,
                "instance_id": iid,
                "resource_type": info.get("ResourceType"),
                "platform_type": info.get("PlatformType", ""),
                "platform_name": info.get("PlatformName"),
                "platform_version": info.get("PlatformVersion"),
                "computer_name": info.get("ComputerName"),
                "private_ip": info.get("IPAddress"),
                "ping_status": info.get("PingStatus", ""),
                "agent_version": info.get("AgentVersion"),
                "activation_id": info.get("ActivationId"),
                "source_id": info.get("SourceId"),
                "source_type": info.get("SourceType"),
            },
            relations=[
                _role_rel(self._role_ref(info.get("IamRole")), "hybrid activation role"),
            ],
            aliases=[iid],
        )

    def _ssm_fleet_entry(
        self, info: dict, stats: dict[str, Any], assets: list[CloudAsset]
    ) -> dict | None:
        """Tally one managed instance; hybrid nodes become their own asset.
        Returns the fleet's MANAGES relation to the instance."""
        iid = info.get("InstanceId", "")
        status = info.get("PingStatus", "")
        stats["ping"][status] = stats["ping"].get(status, 0) + 1
        plat = info.get("PlatformType", "")
        stats["platforms"][plat] = stats["platforms"].get(plat, 0) + 1
        if info.get("IsLatestVersion") is False:
            stats["outdated"] += 1
        props = {
            "ping_status": status,
            "agent_version": info.get("AgentVersion"),
            "platform": info.get("PlatformName"),
            "association_status": info.get("AssociationStatus"),
        }
        if not iid.startswith("mi-"):
            return rel(iid, EdgeType.MANAGES, description="SSM managed instance", **props)
        arn = self._arn("ssm", f"managed-instance/{iid}")
        assets.append(self._ssm_hybrid_node_asset(info, arn))
        return rel(arn, EdgeType.MANAGES, description="SSM hybrid node", **props)

    async def _collect_ssm_managed_instances(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        fleet_relations: list[dict | None] = []
        stats: dict[str, Any] = {"ping": {}, "platforms": {}, "outdated": 0}
        async with self._client("ssm") as ssm:
            async for info in self._paginate(
                ssm, "describe_instance_information", "InstanceInformationList"
            ):
                fleet_relations.append(self._ssm_fleet_entry(info, stats, assets))
        if fleet_relations:
            assets.append(
                self._asset(
                    arn=f"cloudg:aws:ssm:{self._region}:{self._account_id}:fleet",
                    name=f"Systems Manager fleet ({self._region})",
                    asset_type=AssetType.OTHER,
                    metadata={
                        "service": "ssm",
                        "kind": "managed_fleet",
                        "managed_instances": len(fleet_relations),
                        "hybrid_nodes": sum(1 for a in assets if a.metadata.get("hybrid")),
                        "ping_status": stats["ping"],
                        "platforms": stats["platforms"],
                        "outdated_agents": stats["outdated"],
                    },
                    relations=fleet_relations,
                    aliases=[self._security_alias("ssm")],
                )
            )
        return assets

    async def _ssm_document_asset(self, ssm: Any, doc: dict) -> CloudAsset:
        name = doc.get("Name", "")
        accounts: list[str] = []
        try:
            perm = await ssm.describe_document_permission(Name=name, PermissionType="Share")
            accounts = [str(a) for a in perm.get("AccountIds", []) or []]
        except Exception as exc:
            logger.debug("Document permission lookup failed for %s: %s", name, exc)
        public = any(a.lower() == "all" for a in accounts)
        shared = [a for a in accounts if a.lower() != "all"]
        relations = [
            rel(
                principal_ref(a),
                EdgeType.GRANTS_ACCESS,
                "POLICY_ALLOWS_ACTION",
                reverse=True,
                description="document shared with account",
                cross_account=a != self._account_id,
            )
            for a in shared
        ]
        return self._asset(
            arn=name if name.startswith("arn:") else self._arn("ssm", f"document/{name}"),
            name=name,
            asset_type=AssetType.RUNBOOK,
            tags=doc.get("Tags"),
            metadata={
                "service": "ssm",
                "kind": "ssm_document",
                "document_type": doc.get("DocumentType"),
                "document_format": doc.get("DocumentFormat"),
                "document_version": doc.get("DocumentVersion"),
                "platform_types": doc.get("PlatformTypes", []),
                "target_type": doc.get("TargetType"),
                "public": public,
                "shared_with_accounts": shared,
            },
            relations=relations,
            exposed=public,
        )

    async def _collect_ssm_documents(self) -> list[CloudAsset]:
        async with self._client("ssm") as ssm:
            docs = [
                d
                async for d in self._paginate(
                    ssm,
                    "list_documents",
                    "DocumentIdentifiers",
                    Filters=[{"Key": "Owner", "Values": ["Self"]}],
                )
            ]
            results = await gather_limited(
                [lambda d=d: self._ssm_document_asset(ssm, d) for d in docs]
            )
        return [a for a in results if a]

    def _ssm_target_relations(
        self, targets: Any, description: str
    ) -> tuple[list[dict | None], list[dict]]:
        relations: list[dict | None] = []
        summary: list[dict] = []
        for t in targets or []:
            key, values = t.get("Key", ""), t.get("Values", []) or []
            summary.append({"key": key, "values": values[:50]})
            if key in ("InstanceIds", "ResourceId"):
                for v in values:
                    if v != "*":
                        relations.append(
                            rel(v, EdgeType.MANAGES, "SCHEDULED_BY", description=description)
                        )
            elif key in ("resource-groups:Name", "ResourceGroup"):
                for v in values:
                    relations.append(
                        rel(
                            v,
                            EdgeType.MANAGES,
                            "SCHEDULED_BY",
                            description=f"{description} (resource group)",
                        )
                    )
        return relations, summary

    def _ssm_document_ref(self, name: Any) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        if name.startswith("arn:"):
            return name
        if _is_aws_owned_document(name):
            return None
        return self._arn("ssm", f"document/{name}")

    def _ssm_association_asset(self, a: dict) -> CloudAsset:
        aid = a.get("AssociationId", "")
        doc = a.get("Name", "")
        relations, targets = self._ssm_target_relations(
            a.get("Targets"), f"association applies {doc}"
        )
        if a.get("InstanceId"):
            relations.append(
                rel(
                    a["InstanceId"],
                    EdgeType.MANAGES,
                    "SCHEDULED_BY",
                    description=f"association applies {doc}",
                )
            )
        relations.append(
            rel(
                self._ssm_document_ref(doc),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="association document",
            )
        )
        return self._asset(
            arn=self._arn("ssm", f"association/{aid}"),
            name=a.get("AssociationName") or f"{doc} ({aid})",
            asset_type=AssetType.SCHEDULE,
            metadata={
                "service": "ssm",
                "kind": "ssm_association",
                "association_id": aid,
                "document": doc,
                "document_version": a.get("DocumentVersion"),
                "schedule": a.get("ScheduleExpression"),
                "targets": targets,
                "status": (a.get("Overview") or {}).get("Status"),
                "last_execution": str(a.get("LastExecutionDate") or "") or None,
            },
            relations=relations,
            aliases=[aid],
        )

    async def _collect_ssm_associations(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ssm") as ssm:
            async for a in self._paginate(ssm, "list_associations", "Associations"):
                assets.append(self._ssm_association_asset(a))
        return assets

    async def _ssm_window_targets(self, ssm: Any, wid: str, relations: list) -> list[dict]:
        """Maintenance window targets; their relations go into ``relations``."""
        targets: list[dict] = []
        try:
            async for t in self._paginate(
                ssm, "describe_maintenance_window_targets", "Targets", WindowId=wid
            ):
                t_rels, t_summary = self._ssm_target_relations(
                    t.get("Targets"), "maintenance window target"
                )
                relations.extend(t_rels)
                targets.append(
                    {
                        "name": t.get("Name"),
                        "resource_type": t.get("ResourceType"),
                        "targets": t_summary,
                    }
                )
        except Exception as exc:
            logger.debug("Maintenance window targets failed for %s: %s", wid, exc)
        return targets

    def _ssm_window_task_relations(self, task: dict) -> list[dict | None]:
        task_arn = task.get("TaskArn", "")
        ttype = task.get("Type")
        if task_arn.startswith("arn:"):
            target = rel(task_arn, EdgeType.INVOKES, "INVOKES", description=f"{ttype} task")
        else:
            target = rel(
                self._ssm_document_ref(task_arn),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description=f"{ttype} task document",
            )
        log_bucket = (task.get("LoggingInfo") or {}).get("S3BucketName")
        relations: list[dict | None] = [
            target,
            _role_rel(task.get("ServiceRoleArn"), "task role"),
            rel(_bucket_arn(log_bucket), EdgeType.LOGS_TO, "LOGS_TO"),
        ]
        t_rels, _ = self._ssm_target_relations(
            task.get("Targets"), "maintenance window task target"
        )
        return relations + t_rels

    async def _ssm_window_tasks(self, ssm: Any, wid: str, relations: list) -> list[dict]:
        """Maintenance window tasks; their relations go into ``relations``."""
        tasks: list[dict] = []
        try:
            async for task in self._paginate(
                ssm, "describe_maintenance_window_tasks", "Tasks", WindowId=wid
            ):
                relations.extend(self._ssm_window_task_relations(task))
                tasks.append(
                    {
                        "name": task.get("Name"),
                        "type": task.get("Type"),
                        "task": task.get("TaskArn", ""),
                        "priority": task.get("Priority"),
                    }
                )
        except Exception as exc:
            logger.debug("Maintenance window tasks failed for %s: %s", wid, exc)
        return tasks

    async def _ssm_window_asset(self, ssm: Any, w: dict) -> CloudAsset:
        wid = w.get("WindowId", "")
        relations: list[dict | None] = []
        targets = await self._ssm_window_targets(ssm, wid, relations)
        tasks = await self._ssm_window_tasks(ssm, wid, relations)
        return self._asset(
            arn=self._arn("ssm", f"maintenancewindow/{wid}"),
            name=w.get("Name") or wid,
            asset_type=AssetType.SCHEDULE,
            metadata={
                "service": "ssm",
                "kind": "maintenance_window",
                "window_id": wid,
                "enabled": w.get("Enabled"),
                "schedule": w.get("Schedule"),
                "timezone": w.get("ScheduleTimezone"),
                "duration_hours": w.get("Duration"),
                "cutoff_hours": w.get("Cutoff"),
                "next_execution": w.get("NextExecutionTime"),
                "targets": targets,
                "tasks": tasks,
            },
            relations=relations,
            aliases=[wid],
        )

    async def _collect_ssm_maintenance_windows(self) -> list[CloudAsset]:
        async with self._client("ssm") as ssm:
            windows = [
                w
                async for w in self._paginate(
                    ssm, "describe_maintenance_windows", "WindowIdentities"
                )
            ]
            results = await gather_limited(
                [lambda w=w: self._ssm_window_asset(ssm, w) for w in windows]
            )
        return [a for a in results if a]
