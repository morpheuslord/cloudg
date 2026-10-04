"""Analytics: EMR clusters, EMR Serverless applications, Athena workgroups."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.data_ml._common import (
    _EMR_ACTIVE_STATES,
    DataMLHelpersMixin,
    Relations,
    _bucket_arn,
    _gather_details,
    _kms_ref,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


class AnalyticsCollectorsMixin(DataMLHelpersMixin):
    """EMR, EMR Serverless and Athena collectors."""

    # ------------------------------------------------------------------
    # EMR
    # ------------------------------------------------------------------

    async def _collect_emr(self) -> list[CloudAsset]:
        async with self._client("emr") as emr:
            clusters = [
                c
                async for c in self._paginate(
                    emr, "list_clusters", "Clusters", ClusterStates=_EMR_ACTIVE_STATES
                )
            ]
            return await _gather_details(clusters, lambda c: self._emr_cluster(emr, c))

    def _emr_role_rels(self, c: dict, ec2: dict) -> Relations:
        return [
            rel(
                self._dm_role_ref(c.get("ServiceRole")),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="service role",
            ),
            rel(
                self._dm_role_ref(c.get("AutoScalingRole")),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="auto scaling role",
            ),
            rel(
                self._profile_ref(ec2.get("IamInstanceProfile")),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="EC2 instance profile",
            ),
        ]

    async def _emr_cluster(self, emr: Any, summary: dict) -> CloudAsset:
        c = (await emr.describe_cluster(ClusterId=summary["Id"])).get("Cluster") or {}
        ec2 = c.get("Ec2InstanceAttributes") or {}
        subnets = ec2.get("RequestedEc2SubnetIds") or (
            [ec2["Ec2SubnetId"]] if ec2.get("Ec2SubnetId") else []
        )
        sgs = [
            ec2.get("EmrManagedMasterSecurityGroup"),
            ec2.get("EmrManagedSlaveSecurityGroup"),
            ec2.get("ServiceAccessSecurityGroup"),
            *(ec2.get("AdditionalMasterSecurityGroups") or []),
            *(ec2.get("AdditionalSlaveSecurityGroups") or []),
        ]
        kms = _kms_ref(c.get("LogEncryptionKmsKeyId"))
        relations: Relations = self._subnet_rels(subnets)
        relations += self._emr_role_rels(c, ec2)
        relations += [
            rel(_bucket_arn(c.get("LogUri")), EdgeType.LOGS_TO, "LOGS_TO"),
            rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(c.get("OutpostArn"), EdgeType.REFERENCES, "RUNS_ON"),
        ]
        master_dns = c.get("MasterPublicDnsName") or ""
        return self._asset(
            arn=c.get("ClusterArn")
            or summary.get("ClusterArn")
            or self._arn("elasticmapreduce", f"cluster/{summary['Id']}"),
            name=c.get("Name") or summary.get("Name") or summary["Id"],
            asset_type=AssetType.BIG_DATA_CLUSTER,
            tags=c.get("Tags"),
            metadata={
                "service": "emr",
                "cluster_id": summary["Id"],
                "state": (c.get("Status") or {}).get("State"),
                "release_label": c.get("ReleaseLabel"),
                "applications": [a.get("Name") for a in c.get("Applications") or []],
                "security_groups": sorted({g for g in sgs if g}),
                "security_configuration": c.get("SecurityConfiguration"),
                "log_uri": c.get("LogUri"),
                "kms_key_id": kms,
                "master_public_dns": master_dns or None,
                "key_name": ec2.get("Ec2KeyName"),
                "kerberos": bool(c.get("KerberosAttributes")),
                "termination_protected": c.get("TerminationProtected"),
            },
            relations=relations,
            exposed=master_dns.startswith("ec2-"),
            aliases=[summary["Id"], master_dns or None],
        )

    # ------------------------------------------------------------------
    # EMR Serverless
    # ------------------------------------------------------------------

    async def _collect_emr_serverless(self) -> list[CloudAsset]:
        async with self._client("emr-serverless") as emrs:
            apps = [a async for a in self._paginate(emrs, "list_applications", "applications")]
            return await _gather_details(apps, lambda x: self._emr_serverless_app(emrs, x))

    async def _emr_serverless_app(self, emrs: Any, summary: dict) -> CloudAsset:
        a = (await emrs.get_application(applicationId=summary["id"])).get("application") or {}
        net = a.get("networkConfiguration") or {}
        mon = a.get("monitoringConfiguration") or {}
        s3mon = mon.get("s3MonitoringConfiguration") or {}
        cw = mon.get("cloudWatchLoggingConfiguration") or {}
        relations: Relations = self._subnet_rels(net.get("subnetIds"))
        image = (a.get("imageConfiguration") or {}).get("imageUri")
        relations += [
            rel(image, EdgeType.USES_IMAGE, "RUNS_ON"),
            rel(_bucket_arn(s3mon.get("logUri")), EdgeType.LOGS_TO, "LOGS_TO"),
            rel(
                self._log_group_ref(cw.get("logGroupName")) if cw.get("enabled") else None,
                EdgeType.LOGS_TO,
                "LOGS_TO",
            ),
        ]
        for key in {
            _kms_ref(s3mon.get("encryptionKeyArn")),
            _kms_ref(cw.get("encryptionKeyArn")),
        }:
            relations.append(rel(key, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        for spec in (a.get("workerTypeSpecifications") or {}).values():
            relations.append(
                rel(
                    (spec.get("imageConfiguration") or {}).get("imageUri"),
                    EdgeType.USES_IMAGE,
                    "RUNS_ON",
                )
            )
        return self._asset(
            arn=a.get("arn") or summary.get("arn", ""),
            name=a.get("name") or summary.get("name") or summary["id"],
            asset_type=AssetType.BIG_DATA_CLUSTER,
            tags=a.get("tags"),
            metadata={
                "service": "emr-serverless",
                "application_id": summary["id"],
                "type": a.get("type") or summary.get("type"),
                "state": a.get("state") or summary.get("state"),
                "release_label": a.get("releaseLabel"),
                "security_groups": net.get("securityGroupIds") or [],
                "in_vpc": bool(net.get("subnetIds")),
                "image": image,
            },
            relations=relations,
            aliases=[summary["id"]],
        )

    # ------------------------------------------------------------------
    # Athena
    # ------------------------------------------------------------------

    async def _collect_athena(self) -> list[CloudAsset]:
        async with self._client("athena") as athena:
            groups = [g async for g in self._pages(athena.list_work_groups, "WorkGroups")]
            return await _gather_details(groups, lambda g: self._athena_workgroup(athena, g))

    async def _athena_workgroup(self, athena: Any, summary: dict) -> CloudAsset:
        name = summary["Name"]
        wg = (await athena.get_work_group(WorkGroup=name)).get("WorkGroup") or {}
        cfg = wg.get("Configuration") or {}
        result = cfg.get("ResultConfiguration") or {}
        enc = result.get("EncryptionConfiguration") or {}
        managed = cfg.get("ManagedQueryResultsConfiguration") or {}
        keys = {
            _kms_ref(enc.get("KmsKey")),
            _kms_ref(((managed.get("EncryptionConfiguration") or {}).get("KmsKey"))),
            _kms_ref((cfg.get("CustomerContentEncryptionConfiguration") or {}).get("KmsKey")),
        }
        relations: Relations = [
            rel(
                _bucket_arn(result.get("OutputLocation")),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="query results",
            ),
            rel(cfg.get("ExecutionRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]
        relations += [
            rel(k, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS") for k in sorted(k for k in keys if k)
        ]
        return self._asset(
            arn=self._arn("athena", f"workgroup/{name}"),
            name=name,
            asset_type=AssetType.QUERY_WORKGROUP,
            metadata={
                "service": "athena",
                "state": wg.get("State") or summary.get("State"),
                "output_location": result.get("OutputLocation"),
                "encryption": enc.get("EncryptionOption"),
                "kms_key_id": _kms_ref(enc.get("KmsKey")),
                "enforce_workgroup_configuration": cfg.get("EnforceWorkGroupConfiguration"),
                "managed_query_results": managed.get("Enabled"),
                "bytes_scanned_cutoff": cfg.get("BytesScannedCutoffPerQuery"),
                "engine_version": (cfg.get("EngineVersion") or {}).get("EffectiveEngineVersion"),
                "identity_center": (cfg.get("IdentityCenterConfiguration") or {}).get(
                    "EnableIdentityCenter"
                ),
            },
            relations=relations,
        )
