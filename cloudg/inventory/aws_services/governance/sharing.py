"""EBS snapshots, AMIs and manual RDS snapshots with their sharing
permissions (public -> exposed, accounts -> GRANTS_ACCESS)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    gather_limited,
    rel,
)
from cloudg.inventory.aws_services.governance._common import (
    _ACCOUNT_RE,
    _MAX_IMAGES,
    _MAX_SNAPSHOTS,
    _arn_account,
    _principal_target,
    _take,
    _trust_kind,
    _ts,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _restore_values(attrs: dict[str, list[dict]], sid: str) -> list[str]:
    """Values of an RDS snapshot's ``restore`` attribute (accounts / "all")."""
    return [
        str(v)
        for a in attrs.get(sid, [])
        if a.get("AttributeName") == "restore"
        for v in a.get("AttributeValues") or []
    ]


def _image_org_grants(grants: list[dict]) -> list[str]:
    return [
        g.get("OrganizationArn") or g.get("OrganizationalUnitArn")
        for g in grants
        if g.get("OrganizationArn") or g.get("OrganizationalUnitArn")
    ]


class SharingCollectorsMixin(AWSServiceMixin):
    """Snapshot and machine image collectors with sharing permissions."""

    def _share_relations(self, principals: list[str], permission: str) -> list[dict | None]:
        """Account / organization principals a snapshot or image is shared
        with -> GRANTS_ACCESS (principal -> resource)."""
        out: list[dict | None] = []
        for p in principals:
            target = _principal_target(p)
            acct = _arn_account(target or "")
            out.append(
                rel(
                    target,
                    EdgeType.GRANTS_ACCESS,
                    _trust_kind(acct != self._account_id),
                    reverse=True,
                    description=f"shared via {permission}",
                    permission=permission,
                )
            )
        return out

    # -- EBS snapshots ---------------------------------------------------

    async def _collect_ebs_snapshots(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            snaps = await _take(
                self._paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]),
                _MAX_SNAPSHOTS,
            )
            if len(snaps) >= _MAX_SNAPSHOTS:
                logger.warning("EBS snapshots truncated at %d in %s", _MAX_SNAPSHOTS, self._region)
            results = await gather_limited(
                [lambda s=s: self._snapshot_volume_permissions(ec2, s["SnapshotId"]) for s in snaps]
            )
        permissions = {r[0]: r[1] for r in results if r}
        return [self._ebs_snapshot_asset(s, permissions) for s in snaps]

    async def _snapshot_volume_permissions(self, ec2: Any, snap_id: str) -> tuple[str, list[dict]]:
        resp = await ec2.describe_snapshot_attribute(
            Attribute="createVolumePermission", SnapshotId=snap_id
        )
        return snap_id, resp.get("CreateVolumePermissions") or []

    def _ebs_snapshot_asset(
        self, s: dict[str, Any], permissions: dict[str, list[dict]]
    ) -> CloudAsset:
        snap_id = s["SnapshotId"]
        grants = permissions.get(snap_id, [])
        public = any(g.get("Group") == "all" for g in grants)
        accounts = [g["UserId"] for g in grants if g.get("UserId")]
        return self._asset(
            arn=f"arn:aws:ec2:{self._region}::snapshot/{snap_id}",
            name=snap_id,
            asset_type=AssetType.SNAPSHOT,
            tags=s.get("Tags"),
            metadata={
                "snapshot_type": "ebs",
                "snapshot_id": snap_id,
                "source_volume_id": s.get("VolumeId"),
                "size_gb": s.get("VolumeSize"),
                "state": s.get("State"),
                "encrypted": s.get("Encrypted", False),
                "kms_key_id": s.get("KmsKeyId"),
                "started": _ts(s.get("StartTime")),
                "storage_tier": s.get("StorageTier"),
                "description": s.get("Description"),
                "public": public,
                "shared_accounts": accounts,
                "sharing_known": snap_id in permissions,
            },
            relations=[
                rel(s.get("VolumeId"), EdgeType.REFERENCES, description="snapshot of volume"),
                rel(s.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                *self._share_relations(accounts, "createVolumePermission"),
            ],
            raw=s,
            exposed=public,
            aliases=[self._arn("ec2", f"snapshot/{snap_id}")],
        )

    # -- AMIs ------------------------------------------------------------

    async def _collect_machine_images(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            images = await _take(
                self._paginate(ec2, "describe_images", "Images", Owners=["self"]), _MAX_IMAGES
            )
            if len(images) >= _MAX_IMAGES:
                logger.warning("AMIs truncated at %d in %s", _MAX_IMAGES, self._region)
            results = await gather_limited(
                [lambda i=i: self._image_launch_permissions(ec2, i["ImageId"]) for i in images]
            )
        permissions = {r[0]: r[1] for r in results if r}
        return [self._machine_image_asset(img, permissions) for img in images]

    async def _image_launch_permissions(self, ec2: Any, image_id: str) -> tuple[str, list[dict]]:
        resp = await ec2.describe_image_attribute(Attribute="launchPermission", ImageId=image_id)
        return image_id, resp.get("LaunchPermissions") or []

    def _machine_image_relations(
        self, img: dict[str, Any], ebs: list[dict], shared_with: list[str]
    ) -> list[dict | None]:
        snapshots = [e["SnapshotId"] for e in ebs if e.get("SnapshotId")]
        kms_keys = sorted({e["KmsKeyId"] for e in ebs if e.get("KmsKeyId")})
        relations: list[dict | None] = [
            rel(
                f"arn:aws:ec2:{self._region}::snapshot/{sid}",
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="AMI backing snapshot",
            )
            for sid in snapshots
        ]
        relations += [rel(k, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS") for k in kms_keys]
        relations += self._share_relations(shared_with, "launchPermission")
        relations.append(
            rel(
                img.get("SourceInstanceId"),
                EdgeType.REFERENCES,
                description="created from instance",
            )
        )
        return relations

    def _machine_image_asset(
        self, img: dict[str, Any], permissions: dict[str, list[dict]]
    ) -> CloudAsset:
        image_id = img["ImageId"]
        grants = permissions.get(image_id, [])
        public = bool(img.get("Public")) or any(g.get("Group") == "all" for g in grants)
        accounts = [g["UserId"] for g in grants if g.get("UserId")]
        orgs = _image_org_grants(grants)
        ebs = [b["Ebs"] for b in img.get("BlockDeviceMappings") or [] if b.get("Ebs")]
        return self._asset(
            arn=f"arn:aws:ec2:{self._region}::image/{image_id}",
            name=img.get("Name") or image_id,
            asset_type=AssetType.MACHINE_IMAGE,
            tags=img.get("Tags"),
            metadata={
                "image_id": image_id,
                "state": img.get("State"),
                "public": public,
                "platform": img.get("PlatformDetails") or img.get("Platform"),
                "architecture": img.get("Architecture"),
                "created": img.get("CreationDate"),
                "deprecation_time": img.get("DeprecationTime"),
                "last_launched": img.get("LastLaunchedTime"),
                "root_device_type": img.get("RootDeviceType"),
                "imds_support": img.get("ImdsSupport"),
                "source_image_id": img.get("SourceImageId"),
                "snapshots": [e["SnapshotId"] for e in ebs if e.get("SnapshotId")],
                "encrypted": bool(ebs) and all(e.get("Encrypted") for e in ebs),
                "shared_accounts": accounts,
                "shared_organizations": orgs,
                "sharing_known": image_id in permissions,
            },
            relations=self._machine_image_relations(img, ebs, accounts + orgs),
            raw=img,
            exposed=public,
            aliases=[self._arn("ec2", f"image/{image_id}")],
        )

    # -- RDS snapshots ---------------------------------------------------

    async def _collect_rds_snapshots(self) -> list[CloudAsset]:
        async with self._client("rds") as rds:
            instance_snaps = await _take(
                self._paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"),
                _MAX_SNAPSHOTS,
            )
            cluster_snaps: list[dict] = []
            try:
                await _take(
                    self._paginate(
                        rds,
                        "describe_db_cluster_snapshots",
                        "DBClusterSnapshots",
                        SnapshotType="manual",
                    ),
                    _MAX_SNAPSHOTS,
                    cluster_snaps,
                )
            except Exception as exc:
                logger.debug("RDS cluster snapshot listing failed: %s", exc)
            inst_results = await gather_limited(
                [
                    lambda s=s: self._rds_instance_snapshot_attrs(rds, s["DBSnapshotIdentifier"])
                    for s in instance_snaps
                ]
            )
            cl_results = await gather_limited(
                [
                    lambda s=s: self._rds_cluster_snapshot_attrs(
                        rds, s["DBClusterSnapshotIdentifier"]
                    )
                    for s in cluster_snaps
                ]
            )
        attrs = {r[0]: r[1] for r in inst_results + cl_results if r}
        return [
            self._rds_snapshot_asset(s, cluster, attrs)
            for s, cluster in [(s, False) for s in instance_snaps]
            + [(s, True) for s in cluster_snaps]
        ]

    async def _rds_instance_snapshot_attrs(self, rds: Any, sid: str) -> tuple[str, list[dict]]:
        resp = await rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
        return sid, (resp.get("DBSnapshotAttributesResult") or {}).get("DBSnapshotAttributes") or []

    async def _rds_cluster_snapshot_attrs(self, rds: Any, sid: str) -> tuple[str, list[dict]]:
        resp = await rds.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=sid)
        return sid, (resp.get("DBClusterSnapshotAttributesResult") or {}).get(
            "DBClusterSnapshotAttributes"
        ) or []

    def _rds_snapshot_asset(
        self, s: dict[str, Any], cluster: bool, attrs: dict[str, list[dict]]
    ) -> CloudAsset:
        sid = s["DBClusterSnapshotIdentifier"] if cluster else s["DBSnapshotIdentifier"]
        source = s.get("DBClusterIdentifier") if cluster else s.get("DBInstanceIdentifier")
        source_arn = (
            self._arn("rds", f"{'cluster' if cluster else 'db'}:{source}") if source else None
        )
        values = _restore_values(attrs, sid)
        public = "all" in values
        accounts = [v for v in values if _ACCOUNT_RE.match(v)]
        kms_key = s.get("KmsKeyId")
        arn = (s.get("DBClusterSnapshotArn") if cluster else s.get("DBSnapshotArn")) or self._arn(
            "rds", f"{'cluster-snapshot' if cluster else 'snapshot'}:{sid}"
        )
        return self._asset(
            arn=arn,
            name=sid,
            asset_type=AssetType.SNAPSHOT,
            tags=s.get("TagList"),
            metadata={
                "snapshot_type": "rds_cluster" if cluster else "rds",
                "source_identifier": source,
                "engine": s.get("Engine"),
                "engine_version": s.get("EngineVersion"),
                "status": s.get("Status"),
                "encrypted": s.get("StorageEncrypted") if cluster else s.get("Encrypted"),
                "kms_key_id": kms_key,
                "created": _ts(s.get("SnapshotCreateTime")),
                "vpc_id": s.get("VpcId"),
                "public": public,
                "shared_accounts": accounts,
                "sharing_known": sid in attrs,
            },
            relations=[
                rel(source_arn, EdgeType.REFERENCES, description="snapshot of database"),
                rel(kms_key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                *self._share_relations(accounts, "restore"),
            ],
            raw={k: v for k, v in s.items() if k != "MasterUsername"},
            exposed=public,
        )
