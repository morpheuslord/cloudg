"""Data movement and file storage: Transfer Family servers / users, DataSync
tasks and locations, FSx file systems."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.data_ml._common import (
    _EXECUTE_API_HOST_RE,
    _FS_ID_RE,
    _MAX_TRANSFER_USERS,
    DataMLHelpersMixin,
    Relations,
    _bucket_arn,
    _gather_details,
    _host,
    _kms_ref,
    _name_tag,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _identity_rels(s: dict, idp: dict) -> Relations:
    """Logging / identity provider roles, custom IdP Lambda and certificate."""
    return [
        rel(s.get("LoggingRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="logging role"),
        rel(
            idp.get("Function"),
            EdgeType.INVOKES,
            "INVOKES",
            description="custom identity provider",
        ),
        rel(
            idp.get("InvocationRole"),
            EdgeType.ASSUMES_ROLE,
            "RUNS_ON",
            description="identity provider invocation role",
        ),
        rel(s.get("Certificate"), EdgeType.REFERENCES, "CERTIFICATE_SECURES", reverse=True),
    ]


def _api_gateway_idp_rels(idp: dict) -> Relations:
    """INVOKES the API Gateway REST API behind an API_GATEWAY identity
    provider; only a genuine execute-api host yields its API id."""
    api_host = _host(idp.get("Url"))
    if api_host and _EXECUTE_API_HOST_RE.fullmatch(api_host):
        return [
            rel(
                api_host.split(".", 1)[0],
                EdgeType.INVOKES,
                "INVOKES",
                description="API Gateway identity provider",
            )
        ]
    return []


def _workflow_rels(workflows: dict) -> tuple[Relations, list[str]]:
    """(workflow execution role relations, workflow ids)."""
    relations: Relations = []
    wf_ids: list[str] = []
    for key in ("OnUpload", "OnPartialUpload"):
        for wf in workflows.get(key) or []:
            wf_ids.append(wf.get("WorkflowId"))
            relations.append(
                rel(
                    wf.get("ExecutionRole"),
                    EdgeType.ASSUMES_ROLE,
                    "RUNS_ON",
                    description=f"{key} workflow role",
                )
            )
    return relations, wf_ids


def _fsx_storage_rels(f: dict) -> Relations:
    """Data repository paths and audit / log destinations of a file system."""
    windows = f.get("WindowsConfiguration") or {}
    lustre = f.get("LustreConfiguration") or {}
    repo = lustre.get("DataRepositoryConfiguration") or {}
    return [
        rel(
            _bucket_arn(repo.get("ImportPath")),
            EdgeType.REFERENCES,
            "READS_FROM",
            description="import path",
        ),
        rel(
            _bucket_arn(repo.get("ExportPath")),
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="export path",
        ),
        rel(
            (windows.get("AuditLogConfiguration") or {}).get("AuditLogDestination"),
            EdgeType.LOGS_TO,
            "LOGS_TO",
        ),
        rel((lustre.get("LogConfiguration") or {}).get("Destination"), EdgeType.LOGS_TO, "LOGS_TO"),
    ]


class TransferCollectorsMixin(DataMLHelpersMixin):
    """Transfer Family, DataSync and FSx collectors."""

    # ------------------------------------------------------------------
    # Transfer Family
    # ------------------------------------------------------------------

    def _home_rels(self, domain: Any, path: Any, description: str) -> list[dict[str, Any] | None]:
        """READS_FROM the bucket / EFS file system behind a Transfer home path."""
        if not isinstance(path, str) or not path.strip("/"):
            return []
        head = path.strip("/").split("/", 1)[0]
        if domain == "EFS" or head.startswith("fs-"):
            return [rel(head, EdgeType.REFERENCES, "READS_FROM", description=description)]
        return [
            rel(f"arn:aws:s3:::{head}", EdgeType.REFERENCES, "READS_FROM", description=description)
        ]

    async def _collect_transfer_family(self) -> list[CloudAsset]:
        async with self._client("transfer") as transfer:
            servers = [s async for s in self._paginate(transfer, "list_servers", "Servers")]
            results = await _gather_details(servers, lambda x: self._transfer_server(transfer, x))
        return [a for r in results for a in r]

    async def _transfer_users(
        self, transfer: Any, server_id: str, domain: Any, server_arn: str
    ) -> list[CloudAsset]:
        names = []
        try:
            async for u in self._paginate(transfer, "list_users", "Users", ServerId=server_id):
                names.append(u)
                if len(names) >= _MAX_TRANSFER_USERS:
                    break
        except Exception as exc:
            logger.debug("Transfer user listing failed for %s: %s", server_id, exc)
            return []
        return await _gather_details(
            names, lambda x: self._transfer_user(transfer, server_id, domain, server_arn, x)
        )

    async def _transfer_user(
        self, transfer: Any, server_id: str, domain: Any, server_arn: str, summary: dict
    ) -> CloudAsset:
        u = summary
        try:
            u = (
                await transfer.describe_user(ServerId=server_id, UserName=summary["UserName"])
            ).get("User") or summary
        except Exception as exc:
            logger.debug("Transfer user lookup failed: %s", exc)
        relations: Relations = [
            rel(server_arn, EdgeType.CONTAINS, reverse=True),
            rel(u.get("Role"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]
        relations += self._home_rels(domain, u.get("HomeDirectory"), "home directory")
        for m in u.get("HomeDirectoryMappings") or []:
            relations += self._home_rels(domain, m.get("Target"), "home directory mapping")
        return self._asset(
            arn=u.get("Arn")
            or summary.get("Arn")
            or self._arn("transfer", f"user/{server_id}/{summary['UserName']}"),
            name=f"{server_id}/{summary['UserName']}",
            asset_type=AssetType.IDENTITY_USER,
            tags=u.get("Tags"),
            metadata={
                "service": "transfer",
                "server_id": server_id,
                "user_name": summary["UserName"],
                "home_directory": u.get("HomeDirectory"),
                "home_directory_type": u.get("HomeDirectoryType"),
                "ssh_key_count": len(u.get("SshPublicKeys") or [])
                or summary.get("SshPublicKeyCount"),
                "has_session_policy": bool(u.get("Policy")),
            },
            relations=relations,
        )

    def _transfer_server_rels(self, s: dict) -> Relations:
        ep = s.get("EndpointDetails") or {}
        idp = s.get("IdentityProviderDetails") or {}
        relations: Relations = self._subnet_rels(ep.get("SubnetIds"))
        relations.append(rel(ep.get("VpcEndpointId"), EdgeType.ATTACHED_TO))
        relations += _identity_rels(s, idp)
        relations += [
            rel(a, EdgeType.ATTACHED_TO, reverse=True) for a in ep.get("AddressAllocationIds") or []
        ]
        relations += _api_gateway_idp_rels(idp)
        relations += [
            rel(self._log_group_ref(d), EdgeType.LOGS_TO, "LOGS_TO")
            for d in s.get("StructuredLogDestinations") or []
        ]
        return relations

    async def _transfer_server(self, transfer: Any, summary: dict) -> list[CloudAsset]:
        server_id = summary["ServerId"]
        s = (await transfer.describe_server(ServerId=server_id)).get("Server") or summary
        ep = s.get("EndpointDetails") or {}
        endpoint_type = s.get("EndpointType")
        exposed = endpoint_type == "PUBLIC" or (
            endpoint_type == "VPC" and bool(ep.get("AddressAllocationIds"))
        )
        relations = self._transfer_server_rels(s)
        wf_rels, wf_ids = _workflow_rels(s.get("WorkflowDetails") or {})
        relations += wf_rels
        arn = s.get("Arn") or summary.get("Arn") or self._arn("transfer", f"server/{server_id}")
        tags = s.get("Tags")
        server = self._asset(
            arn=arn,
            name=_name_tag(tags) or server_id,
            asset_type=AssetType.DATA_TRANSFER,
            tags=tags,
            metadata={
                "service": "transfer",
                "kind": "server",
                "server_id": server_id,
                "endpoint_type": endpoint_type,
                "identity_provider_type": s.get("IdentityProviderType"),
                "directory_id": (s.get("IdentityProviderDetails") or {}).get("DirectoryId"),
                "domain": s.get("Domain"),
                "protocols": s.get("Protocols") or [],
                "state": s.get("State"),
                "security_policy": s.get("SecurityPolicyName"),
                "vpc_id": ep.get("VpcId"),
                "security_groups": ep.get("SecurityGroupIds") or [],
                "workflows": [w for w in wf_ids if w],
                "user_count": s.get("UserCount"),
            },
            relations=relations,
            exposed=exposed,
            aliases=[server_id, f"{server_id}.server.transfer.{self._region}.amazonaws.com"],
        )
        return [server, *await self._transfer_users(transfer, server_id, s.get("Domain"), arn)]

    # ------------------------------------------------------------------
    # DataSync
    # ------------------------------------------------------------------

    def _location_target(self, uri: Any) -> str | None:
        """Underlying resource of a DataSync location URI (S3 bucket / EFS / FSx)."""
        bucket = _bucket_arn(uri)
        if bucket:
            return bucket
        if isinstance(uri, str) and uri.split("://", 1)[0] in (
            "efs",
            "fsxw",
            "fsxl",
            "fsxz",
            "fsxn",
        ):
            m = _FS_ID_RE.search(uri)
            return m.group(1) if m else None
        return None

    async def _collect_datasync(self) -> list[CloudAsset]:
        async with self._client("datasync") as ds:
            locations = [loc async for loc in self._paginate(ds, "list_locations", "Locations")]
            tasks = [t async for t in self._paginate(ds, "list_tasks", "Tasks")]
            uris = {loc["LocationArn"]: loc.get("LocationUri") for loc in locations}
            loc_assets = await _gather_details(locations, lambda x: self._datasync_location(ds, x))
            task_assets = await _gather_details(tasks, lambda x: self._datasync_task(ds, uris, x))
        return loc_assets + task_assets

    async def _datasync_location(self, ds: Any, loc: dict) -> CloudAsset:
        arn = loc["LocationArn"]
        uri = loc.get("LocationUri") or ""
        scheme = uri.split("://", 1)[0] if "://" in uri else None
        relations: Relations = [
            rel(
                self._location_target(uri),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="location storage",
            ),
        ]
        if scheme == "s3":
            try:
                s3 = await ds.describe_location_s3(LocationArn=arn)
                relations.append(
                    rel(
                        (s3.get("S3Config") or {}).get("BucketAccessRoleArn"),
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="bucket access role",
                    )
                )
            except Exception as exc:
                logger.debug("DataSync S3 location lookup failed: %s", exc)
        host = None if scheme in ("s3", "efs") or (scheme or "").startswith("fsx") else _host(uri)
        return self._asset(
            arn=arn,
            name=uri or arn,
            asset_type=AssetType.DATA_TRANSFER,
            metadata={
                "service": "datasync",
                "kind": "location",
                "location_uri": uri,
                "location_type": scheme,
                "host": host,
            },
            relations=relations,
        )

    def _datasync_task_rels(self, t: dict, uris: dict[str, Any]) -> Relations:
        src, dst = t.get("SourceLocationArn"), t.get("DestinationLocationArn")
        report = ((t.get("TaskReportConfig") or {}).get("Destination") or {}).get("S3") or {}
        return [
            rel(src, EdgeType.REFERENCES, "READS_FROM", description="source location"),
            rel(dst, EdgeType.REFERENCES, "WRITES_TO", description="destination location"),
            rel(
                self._location_target(uris.get(src)),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="source storage",
            ),
            rel(
                self._location_target(uris.get(dst)),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="destination storage",
            ),
            rel(self._log_group_ref(t.get("CloudWatchLogGroupArn")), EdgeType.LOGS_TO, "LOGS_TO"),
            rel(
                report.get("S3BucketArn"),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="task report",
            ),
            rel(report.get("BucketAccessRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]

    async def _datasync_task(self, ds: Any, uris: dict[str, Any], summary: dict) -> CloudAsset:
        t = await ds.describe_task(TaskArn=summary["TaskArn"])
        src, dst = t.get("SourceLocationArn"), t.get("DestinationLocationArn")
        return self._asset(
            arn=summary["TaskArn"],
            name=t.get("Name") or summary.get("Name") or summary["TaskArn"].rsplit("/", 1)[-1],
            asset_type=AssetType.DATA_TRANSFER,
            metadata={
                "service": "datasync",
                "kind": "task",
                "status": t.get("Status"),
                "task_mode": t.get("TaskMode"),
                "source": uris.get(src) or src,
                "destination": uris.get(dst) or dst,
                "schedule": (t.get("Schedule") or {}).get("ScheduleExpression"),
                "verify_mode": (t.get("Options") or {}).get("VerifyMode"),
            },
            relations=self._datasync_task_rels(t, uris),
        )

    # ------------------------------------------------------------------
    # FSx
    # ------------------------------------------------------------------

    async def _collect_fsx(self) -> list[CloudAsset]:
        async with self._client("fsx") as fsx:
            systems = [f async for f in self._paginate(fsx, "describe_file_systems", "FileSystems")]
        eni_sgs = await self._eni_security_groups(
            sorted({e for f in systems for e in f.get("NetworkInterfaceIds") or []})
        )
        return [self._fsx_file_system(f, eni_sgs) for f in systems]

    async def _eni_security_groups(self, enis: list[str]) -> dict[str, list[str]]:
        """ENI id -> security group ids (FSx does not report them itself)."""
        eni_sgs: dict[str, list[str]] = {}
        if not enis:
            return eni_sgs
        try:
            async with self._client("ec2") as ec2:
                for i in range(0, len(enis), 200):
                    async for eni in self._paginate(
                        ec2,
                        "describe_network_interfaces",
                        "NetworkInterfaces",
                        NetworkInterfaceIds=enis[i : i + 200],
                    ):
                        eni_sgs[eni["NetworkInterfaceId"]] = [
                            g["GroupId"] for g in eni.get("Groups") or []
                        ]
        except Exception as exc:
            logger.debug("FSx ENI security group lookup failed: %s", exc)
        return eni_sgs

    def _fsx_file_system(self, f: dict, eni_sgs: dict[str, list[str]]) -> CloudAsset:
        fs_id = f["FileSystemId"]
        kms = _kms_ref(f.get("KmsKeyId"))
        windows = f.get("WindowsConfiguration") or {}
        lustre = f.get("LustreConfiguration") or {}
        ontap = f.get("OntapConfiguration") or {}
        relations: Relations = self._subnet_rels(f.get("SubnetIds"))
        relations.append(rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        relations += _fsx_storage_rels(f)
        relations += [
            rel(e, EdgeType.ATTACHED_TO, reverse=True) for e in f.get("NetworkInterfaceIds") or []
        ]
        sgs = sorted({g for e in f.get("NetworkInterfaceIds") or [] for g in eni_sgs.get(e, [])})
        self_managed = windows.get("SelfManagedActiveDirectoryConfiguration") or {}
        aliases = [fs_id, f.get("DNSName"), *[a.get("Name") for a in windows.get("Aliases") or []]]
        return self._asset(
            arn=f.get("ResourceARN") or self._arn("fsx", f"file-system/{fs_id}"),
            name=_name_tag(f.get("Tags")) or fs_id,
            asset_type=AssetType.FILE_SYSTEM,
            tags=f.get("Tags"),
            metadata={
                "service": "fsx",
                "file_system_id": fs_id,
                "file_system_type": f.get("FileSystemType"),
                "lifecycle": f.get("Lifecycle"),
                "storage_capacity_gb": f.get("StorageCapacity"),
                "vpc_id": f.get("VpcId"),
                "dns_name": f.get("DNSName"),
                "kms_key_id": kms,
                "security_groups": sgs,
                "active_directory_id": windows.get("ActiveDirectoryId"),
                "self_managed_ad_domain": self_managed.get("DomainName"),
                "deployment_type": windows.get("DeploymentType")
                or lustre.get("DeploymentType")
                or ontap.get("DeploymentType"),
            },
            relations=relations,
            aliases=aliases,
        )
