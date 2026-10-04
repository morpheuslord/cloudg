"""Platform, data, DNS and deployment services.

- S3 (deep): real bucket region, encryption key, event notifications
  (-> Lambda / SQS / SNS), replication, access logging, policy grants.
- Load balancing: ALB/NLB listeners + certificates + access logs, target
  groups -> registered targets, classic ELBs -> instances.
- Auto Scaling groups -> instances / launch templates / target groups,
  launch templates (AMI, instance profile, SGs).
- Data: RDS instances + Aurora clusters (deep), EFS (+ mount targets and
  access points), ElastiCache, OpenSearch, Redshift.
- DNS: Route 53 zones and alias / CNAME / A records -> what they resolve to.
- Deployment: CloudFormation stacks -> every resource they manage.
- Operations: CloudWatch log groups, ACM certificates -> what uses them,
  VPC endpoints, VPC flow logs.
"""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    error_code,
    gather_limited,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

_MAX_RECORDS_PER_ZONE = 2000
_ACM_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]
_DNS_RECORD_TYPES = {"A", "AAAA", "CNAME"}


def _dns(name: str | None) -> str:
    """Normalise a DNS name for matching (lowercase, no trailing dot/dualstack)."""
    if not name:
        return ""
    n = name.lower().rstrip(".")
    return n[len("dualstack.") :] if n.startswith("dualstack.") else n


class PlatformCollectorsMixin(AWSServiceMixin):
    _stack_resources: bool = True

    # ------------------------------------------------------------------
    # S3 (overrides the shallow base collector)
    # ------------------------------------------------------------------

    async def _collect_s3(self) -> list[CloudAsset]:
        async with self._client("s3") as s3:
            buckets = [b async for b in self._paginate(s3, "list_buckets", "Buckets")]

            # Account-level Block Public Access overrides bucket policies.
            account_pab: dict[str, Any] = {}
            try:
                async with self._client("s3control") as s3c:
                    resp = await s3c.get_public_access_block(AccountId=self._account_id)
                    account_pab = resp.get("PublicAccessBlockConfiguration") or {}
            except Exception as exc:
                if "NoSuchPublicAccessBlockConfiguration" not in error_code(exc):
                    logger.debug("Account public access block unavailable: %s", exc)

            async def safe(call: Any, **kwargs: Any) -> dict:
                try:
                    return await call(**kwargs)
                except Exception as exc:
                    code = error_code(exc)
                    if not code.startswith("NoSuch") and "NotFound" not in code:
                        logger.debug("S3 %s failed: %s", getattr(call, "__name__", call), exc)
                    return {}

            async def detail(bucket: dict) -> CloudAsset:
                name = bucket["Name"]
                region = bucket.get("BucketRegion")
                if not region:
                    loc = (await safe(s3.get_bucket_location, Bucket=name)).get("LocationConstraint")
                    region = loc or "us-east-1"
                if region == "EU":
                    region = "eu-west-1"
                enc_rules = ((await safe(s3.get_bucket_encryption, Bucket=name)).get("ServerSideEncryptionConfiguration") or {}).get("Rules", [])
                sse = (enc_rules[0].get("ApplyServerSideEncryptionByDefault") or {}) if enc_rules else {}
                pab = (await safe(s3.get_public_access_block, Bucket=name)).get("PublicAccessBlockConfiguration")
                acl = await safe(s3.get_bucket_acl, Bucket=name)
                notif = await safe(s3.get_bucket_notification_configuration, Bucket=name)
                repl = (await safe(s3.get_bucket_replication, Bucket=name)).get("ReplicationConfiguration") or {}
                logging_cfg = (await safe(s3.get_bucket_logging, Bucket=name)).get("LoggingEnabled") or {}
                policy = (await safe(s3.get_bucket_policy, Bucket=name)).get("Policy")

                relations: list[dict | None] = [
                    rel(sse.get("KMSMasterKeyID"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                ]
                for key, proto in (("LambdaFunctionConfigurations", "LambdaFunctionArn"),
                                   ("QueueConfigurations", "QueueArn"),
                                   ("TopicConfigurations", "TopicArn")):
                    for cfg in notif.get(key, []) or []:
                        relations.append(rel(cfg.get(proto), EdgeType.INVOKES, "INVOKES",
                                             description="event notification", events=cfg.get("Events")))
                for rule in repl.get("Rules", []) or []:
                    dest = rule.get("Destination") or {}
                    relations.append(rel(dest.get("Bucket"), EdgeType.REFERENCES, "REPLICATES_TO",
                                         destination_account=dest.get("Account")))
                relations.append(rel(repl.get("Role"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="replication role"))
                if logging_cfg.get("TargetBucket"):
                    relations.append(rel(f"arn:aws:s3:::{logging_cfg['TargetBucket']}", EdgeType.LOGS_TO, "LOGS_TO"))
                public_policy = False
                for st in policy_statements(policy):
                    if st.get("Effect") != "Allow":
                        continue
                    for p in policy_principals(st).get("AWS", []):
                        if p == "*":
                            public_policy = public_policy or not st.get("Condition")
                            continue
                        relations.append(rel(principal_ref(p), EdgeType.GRANTS_ACCESS, "READS_FROM", reverse=True,
                                             description="bucket policy grant"))
                blocked = any(
                    bool(cfg) and all(cfg.get(k) for k in ("BlockPublicPolicy", "RestrictPublicBuckets"))
                    for cfg in (pab, account_pab)
                )
                return self._asset(
                    arn=f"arn:aws:s3:::{name}",
                    name=name,
                    asset_type=AssetType.S3_BUCKET,
                    region=region,
                    metadata={
                        "creation_date": str(bucket.get("CreationDate", "")),
                        "acl_grants": len(acl.get("Grants", [])) if acl else None,
                        "public_access_block": pab,
                        "account_public_access_block": account_pab or None,
                        "encryption": bool(sse),
                        "sse_algorithm": sse.get("SSEAlgorithm"),
                        "kms_key_id": sse.get("KMSMasterKeyID"),
                        "eventbridge_notifications": "EventBridgeConfiguration" in notif,
                        "replication_rules": len(repl.get("Rules", []) or []),
                        "access_logging_target": logging_cfg.get("TargetBucket"),
                        "policy_allows_public": public_policy and not blocked,
                    },
                    relations=relations,
                    raw=bucket,
                    exposed=public_policy and not blocked,
                    aliases=[f"{name}.s3.amazonaws.com", f"{name}.s3.{region}.amazonaws.com"],
                )

            results = await gather_limited([lambda b=b: detail(b) for b in buckets])
            return [a for a in results if a]

    # ------------------------------------------------------------------
    # Load balancing (overrides the shallow ELBv2 collector)
    # ------------------------------------------------------------------

    async def _collect_elbv2(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("elbv2") as elb:
            lbs = [lb async for lb in self._paginate(elb, "describe_load_balancers", "LoadBalancers")]

            async def lb_detail(lb: dict) -> CloudAsset:
                arn = lb["LoadBalancerArn"]
                relations: list[dict | None] = []
                listeners = []
                async for listener in self._paginate(elb, "describe_listeners", "Listeners", LoadBalancerArn=arn):
                    listeners.append({"port": listener.get("Port"), "protocol": listener.get("Protocol"),
                                      "ssl_policy": listener.get("SslPolicy")})
                    for cert in listener.get("Certificates", []) or []:
                        relations.append(rel(cert.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES"))
                attrs = {}
                try:
                    resp = await elb.describe_load_balancer_attributes(LoadBalancerArn=arn)
                    attrs = {a["Key"]: a["Value"] for a in resp.get("Attributes", [])}
                except Exception as exc:
                    logger.debug("LB attributes unavailable for %s: %s", arn, exc)
                if attrs.get("access_logs.s3.enabled") == "true" and attrs.get("access_logs.s3.bucket"):
                    relations.append(rel(f"arn:aws:s3:::{attrs['access_logs.s3.bucket']}", EdgeType.LOGS_TO, "LOGS_TO"))
                for az in lb.get("AvailabilityZones", []) or []:
                    relations.append(rel(az.get("SubnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
                internet = lb.get("Scheme") == "internet-facing"
                return self._asset(
                    arn=arn,
                    name=lb.get("LoadBalancerName", ""),
                    asset_type=AssetType.LOAD_BALANCER,
                    metadata={
                        "type": lb.get("Type"),
                        "scheme": lb.get("Scheme"),
                        "vpc_id": lb.get("VpcId"),
                        "state": (lb.get("State") or {}).get("Code"),
                        "dns_name": lb.get("DNSName"),
                        "security_groups": lb.get("SecurityGroups", []),
                        "listeners": listeners,
                        "deletion_protection": attrs.get("deletion_protection.enabled") == "true",
                        "drops_invalid_headers": attrs.get("routing.http.drop_invalid_header_fields.enabled") == "true",
                    },
                    relations=relations,
                    raw=lb,
                    exposed=internet,
                    aliases=[_dns(lb.get("DNSName"))],
                )

            results = await gather_limited([lambda lb=lb: lb_detail(lb) for lb in lbs])
            assets.extend(a for a in results if a)

            tgs = [tg async for tg in self._paginate(elb, "describe_target_groups", "TargetGroups")]

            async def tg_detail(tg: dict) -> CloudAsset:
                arn = tg["TargetGroupArn"]
                relations: list[dict | None] = [
                    rel(lb_arn, EdgeType.LOAD_BALANCER_TARGET, "LOAD_BALANCED_BY", reverse=True)
                    for lb_arn in tg.get("LoadBalancerArns", []) or []
                ]
                targets = []
                try:
                    health = await elb.describe_target_health(TargetGroupArn=arn)
                    for desc in health.get("TargetHealthDescriptions", []):
                        tid = (desc.get("Target") or {}).get("Id")
                        state = (desc.get("TargetHealth") or {}).get("State")
                        targets.append({"id": tid, "port": (desc.get("Target") or {}).get("Port"), "state": state})
                        relations.append(rel(tid, EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE", health=state))
                except Exception as exc:
                    logger.debug("Target health unavailable for %s: %s", arn, exc)
                return self._asset(
                    arn=arn,
                    name=tg.get("TargetGroupName", ""),
                    asset_type=AssetType.TARGET_GROUP,
                    metadata={
                        "target_type": tg.get("TargetType"),
                        "protocol": tg.get("Protocol"),
                        "port": tg.get("Port"),
                        "vpc_id": tg.get("VpcId"),
                        "targets": targets,
                    },
                    relations=relations,
                )

            results = await gather_limited([lambda tg=tg: tg_detail(tg) for tg in tgs])
            assets.extend(a for a in results if a)
        return assets

    async def _collect_elb_classic(self) -> list[CloudAsset]:
        async with self._client("elb") as elb:
            out = []
            async for lb in self._paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions"):
                name = lb.get("LoadBalancerName", "")
                relations = [
                    rel(i.get("InstanceId"), EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE")
                    for i in lb.get("Instances", []) or []
                ]
                relations += [rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in lb.get("Subnets", []) or []]
                out.append(
                    self._asset(
                        arn=self._arn("elasticloadbalancing", f"loadbalancer/{name}"),
                        name=name,
                        asset_type=AssetType.LOAD_BALANCER,
                        metadata={
                            "type": "classic",
                            "scheme": lb.get("Scheme"),
                            "vpc_id": lb.get("VPCId"),
                            "dns_name": lb.get("DNSName"),
                            "security_groups": lb.get("SecurityGroups", []),
                        },
                        relations=relations,
                        exposed=lb.get("Scheme") == "internet-facing",
                        aliases=[_dns(lb.get("DNSName"))],
                    )
                )
            return out

    # ------------------------------------------------------------------
    # Compute fabric
    # ------------------------------------------------------------------

    async def _collect_autoscaling(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("autoscaling") as asg_client:
            async for g in self._paginate(asg_client, "describe_auto_scaling_groups", "AutoScalingGroups"):
                lt = g.get("LaunchTemplate") or ((g.get("MixedInstancesPolicy") or {}).get("LaunchTemplate") or {}).get("LaunchTemplateSpecification") or {}
                relations: list[dict | None] = [
                    rel(lt.get("LaunchTemplateId"), EdgeType.REFERENCES, "DEPENDS_ON", description="launch template"),
                    rel(g.get("ServiceLinkedRoleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                ]
                relations += [rel(i.get("InstanceId"), EdgeType.MANAGES, "SCALES_WITH") for i in g.get("Instances", []) or []]
                relations += [rel(tg, EdgeType.LOAD_BALANCER_TARGET, "LOAD_BALANCED_BY", reverse=True) for tg in g.get("TargetGroupARNs", []) or []]
                subnets = [s.strip() for s in (g.get("VPCZoneIdentifier") or "").split(",") if s.strip()]
                relations += [rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in subnets]
                assets.append(
                    self._asset(
                        arn=g["AutoScalingGroupARN"],
                        name=g["AutoScalingGroupName"],
                        asset_type=AssetType.AUTOSCALING_GROUP,
                        tags=g.get("Tags"),
                        metadata={
                            "min_size": g.get("MinSize"),
                            "max_size": g.get("MaxSize"),
                            "desired_capacity": g.get("DesiredCapacity"),
                            "instance_count": len(g.get("Instances", []) or []),
                            "launch_template": lt.get("LaunchTemplateName") or lt.get("LaunchTemplateId"),
                            "launch_configuration": g.get("LaunchConfigurationName"),
                            "health_check_type": g.get("HealthCheckType"),
                        },
                        relations=relations,
                    )
                )
        return assets

    async def _collect_launch_templates(self) -> list[CloudAsset]:
        async with self._client("ec2") as ec2:
            templates = [t async for t in self._paginate(ec2, "describe_launch_templates", "LaunchTemplates")]

            async def detail(t: dict) -> CloudAsset:
                data: dict[str, Any] = {}
                try:
                    resp = await ec2.describe_launch_template_versions(LaunchTemplateId=t["LaunchTemplateId"], Versions=["$Latest"])
                    versions = resp.get("LaunchTemplateVersions", [])
                    data = versions[0].get("LaunchTemplateData", {}) if versions else {}
                except Exception as exc:
                    logger.debug("Launch template version lookup failed: %s", exc)
                profile = (data.get("IamInstanceProfile") or {})
                sgs = list(data.get("SecurityGroupIds", []) or [])
                for ni in data.get("NetworkInterfaces", []) or []:
                    sgs.extend(ni.get("Groups", []) or [])
                return self._asset(
                    arn=self._arn("ec2", f"launch-template/{t['LaunchTemplateId']}"),
                    name=t.get("LaunchTemplateName", t["LaunchTemplateId"]),
                    asset_type=AssetType.LAUNCH_TEMPLATE,
                    tags=t.get("Tags"),
                    metadata={
                        "launch_template_id": t["LaunchTemplateId"],
                        "latest_version": t.get("LatestVersionNumber"),
                        "image_id": data.get("ImageId"),
                        "instance_type": data.get("InstanceType"),
                        "security_groups": sgs,
                        "imdsv2_required": (data.get("MetadataOptions") or {}).get("HttpTokens") == "required",
                    },
                    relations=[rel(profile.get("Arn") or profile.get("Name"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="instance profile")],
                    aliases=[t["LaunchTemplateId"]],
                )

            results = await gather_limited([lambda t=t: detail(t) for t in templates])
            return [a for a in results if a]

    async def _collect_vpc_endpoints(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ec2") as ec2:
            async for ep in self._paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
                relations: list[dict | None] = [
                    rel(ep.get("VpcId"), EdgeType.CONTAINS, reverse=True),
                    rel(ep.get("ServiceName"), EdgeType.ROUTE, "SERVES_TRAFFIC_TO", description="consumes endpoint service"),
                ]
                relations += [rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in ep.get("SubnetIds", []) or []]
                relations += [rel(r, EdgeType.ROUTE, "TRANSIT_ROUTED", reverse=True) for r in ep.get("RouteTableIds", []) or []]
                assets.append(
                    self._asset(
                        arn=self._arn("ec2", f"vpc-endpoint/{ep['VpcEndpointId']}"),
                        name=ep.get("ServiceName", ep["VpcEndpointId"]),
                        asset_type=AssetType.VPC_ENDPOINT,
                        tags=ep.get("Tags"),
                        metadata={
                            "vpc_endpoint_id": ep["VpcEndpointId"],
                            "service_name": ep.get("ServiceName"),
                            "endpoint_type": ep.get("VpcEndpointType"),
                            "state": ep.get("State"),
                            "private_dns": ep.get("PrivateDnsEnabled"),
                            "security_groups": [g.get("GroupId") for g in ep.get("Groups", []) or []],
                        },
                        relations=relations,
                        aliases=[ep["VpcEndpointId"]],
                    )
                )
        return assets

    async def _collect_flow_logs(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ec2") as ec2:
            async for fl in self._paginate(ec2, "describe_flow_logs", "FlowLogs"):
                dest = fl.get("LogDestination")
                if not dest and fl.get("LogGroupName"):
                    dest = self._arn("logs", f"log-group:{fl['LogGroupName']}")
                if dest and dest.startswith("arn:aws:s3:::"):
                    dest = dest.split("/", 1)[0]
                assets.append(
                    self._asset(
                        arn=self._arn("ec2", f"vpc-flow-log/{fl['FlowLogId']}"),
                        name=fl["FlowLogId"],
                        asset_type=AssetType.FLOW_LOG,
                        tags=fl.get("Tags"),
                        metadata={
                            "flow_log_id": fl["FlowLogId"],
                            "monitored_resource": fl.get("ResourceId"),
                            "traffic_type": fl.get("TrafficType"),
                            "destination_type": fl.get("LogDestinationType"),
                            "status": fl.get("FlowLogStatus"),
                        },
                        relations=[
                            rel(fl.get("ResourceId"), EdgeType.MONITORS, "MONITORED_BY", description="flow logging"),
                            rel(dest, EdgeType.LOGS_TO, "LOGS_TO"),
                            rel(fl.get("DeliverLogsPermissionArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                        ],
                    )
                )
        return assets

    # ------------------------------------------------------------------
    # Data services
    # ------------------------------------------------------------------

    async def _collect_rds(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("rds") as rds:
            async for db in self._paginate(rds, "describe_db_instances", "DBInstances"):
                group = db.get("DBSubnetGroup") or {}
                relations: list[dict | None] = [
                    rel(db.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(db.get("DBClusterIdentifier"), EdgeType.CONTAINS, reverse=True, description="cluster member"),
                    rel(db.get("MonitoringRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                    rel(db.get("ReadReplicaSourceDBInstanceIdentifier"), EdgeType.REFERENCES, "REPLICATES_TO", reverse=True),
                ]
                relations += [rel(s.get("SubnetIdentifier"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in group.get("Subnets", []) or []]
                relations += [rel(r.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON", feature=r.get("FeatureName")) for r in db.get("AssociatedRoles", []) or []]
                secret = (db.get("MasterUserSecret") or {}).get("SecretArn")
                relations.append(rel(secret, EdgeType.REFERENCES, "READS_FROM", description="managed master secret"))
                assets.append(
                    self._asset(
                        arn=db.get("DBInstanceArn", ""),
                        name=db.get("DBInstanceIdentifier", ""),
                        asset_type=AssetType.RDS_INSTANCE,
                        tags=db.get("TagList"),
                        metadata={
                            "engine": db.get("Engine"),
                            "engine_version": db.get("EngineVersion"),
                            "instance_class": db.get("DBInstanceClass"),
                            "multi_az": db.get("MultiAZ", False),
                            "publicly_accessible": db.get("PubliclyAccessible", False),
                            "storage_encrypted": db.get("StorageEncrypted", False),
                            "kms_key_id": db.get("KmsKeyId"),
                            "vpc_id": group.get("VpcId"),
                            "security_groups": [g.get("VpcSecurityGroupId") for g in db.get("VpcSecurityGroups", []) or []],
                            "endpoint": (db.get("Endpoint") or {}).get("Address"),
                            "cluster": db.get("DBClusterIdentifier"),
                            "deletion_protection": db.get("DeletionProtection"),
                        },
                        relations=relations,
                        raw=db,
                        exposed=bool(db.get("PubliclyAccessible")),
                        aliases=[(db.get("Endpoint") or {}).get("Address")],
                    )
                )
            try:
                async for c in self._paginate(rds, "describe_db_clusters", "DBClusters"):
                    relations = [
                        rel(c.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                        rel((c.get("MasterUserSecret") or {}).get("SecretArn"), EdgeType.REFERENCES, "READS_FROM"),
                    ]
                    relations += [rel(r.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON") for r in c.get("AssociatedRoles", []) or []]
                    assets.append(
                        self._asset(
                            arn=c["DBClusterArn"],
                            name=c.get("DBClusterIdentifier", ""),
                            asset_type=AssetType.AURORA_CLUSTER,
                            tags=c.get("TagList"),
                            metadata={
                                "engine": c.get("Engine"),
                                "engine_version": c.get("EngineVersion"),
                                "status": c.get("Status"),
                                "storage_encrypted": c.get("StorageEncrypted"),
                                "kms_key_id": c.get("KmsKeyId"),
                                "security_groups": [g.get("VpcSecurityGroupId") for g in c.get("VpcSecurityGroups", []) or []],
                                "members": [m.get("DBInstanceIdentifier") for m in c.get("DBClusterMembers", []) or []],
                                "endpoint": c.get("Endpoint"),
                            },
                            relations=relations,
                            exposed=bool(c.get("PubliclyAccessible")),
                            aliases=[c.get("DBClusterIdentifier"), c.get("Endpoint"), c.get("ReaderEndpoint")],
                        )
                    )
            except Exception as exc:
                logger.debug("RDS cluster listing failed: %s", exc)
        return assets

    async def _collect_efs(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("efs") as efs:
            access_points: dict[str, list[str]] = {}
            try:
                async for ap in self._paginate(efs, "describe_access_points", "AccessPoints"):
                    access_points.setdefault(ap.get("FileSystemId", ""), []).append(ap.get("AccessPointArn"))
            except Exception as exc:
                logger.debug("EFS access point listing failed: %s", exc)
            async for fs in self._paginate(efs, "describe_file_systems", "FileSystems"):
                fs_id = fs["FileSystemId"]
                relations: list[dict | None] = [rel(fs.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")]
                sgs: list[str] = []
                try:
                    async for mt in self._paginate(efs, "describe_mount_targets", "MountTargets", FileSystemId=fs_id):
                        relations.append(rel(mt.get("SubnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True))
                        try:
                            resp = await efs.describe_mount_target_security_groups(MountTargetId=mt["MountTargetId"])
                            sgs.extend(resp.get("SecurityGroups", []))
                        except Exception as exc:
                            logger.debug("Mount target SG lookup failed: %s", exc)
                except Exception as exc:
                    logger.debug("Mount target listing failed for %s: %s", fs_id, exc)
                assets.append(
                    self._asset(
                        arn=fs.get("FileSystemArn") or self._arn("elasticfilesystem", f"file-system/{fs_id}"),
                        name=fs.get("Name") or fs_id,
                        asset_type=AssetType.FILE_SYSTEM,
                        tags=fs.get("Tags"),
                        metadata={
                            "file_system_id": fs_id,
                            "encrypted": fs.get("Encrypted"),
                            "kms_key_id": fs.get("KmsKeyId"),
                            "performance_mode": fs.get("PerformanceMode"),
                            "size_bytes": (fs.get("SizeInBytes") or {}).get("Value"),
                            "security_groups": sorted(set(sgs)),
                        },
                        relations=relations,
                        aliases=[fs_id, *access_points.get(fs_id, [])],
                    )
                )
        return assets

    async def _collect_elasticache(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("elasticache") as ec:
            nodes = {
                cc["CacheClusterId"]: cc
                async for cc in self._paginate(ec, "describe_cache_clusters", "CacheClusters")
            }

            def node_sgs(cc: dict) -> list[str]:
                return [g.get("SecurityGroupId") for g in cc.get("SecurityGroups", []) or []]

            grouped: set[str] = set()
            async for rg in self._paginate(ec, "describe_replication_groups", "ReplicationGroups"):
                members = rg.get("MemberClusters", []) or []
                grouped.update(members)
                sgs = sorted({sg for m in members for sg in node_sgs(nodes.get(m, {})) if sg})
                assets.append(
                    self._asset(
                        arn=rg.get("ARN") or self._arn("elasticache", f"replicationgroup:{rg['ReplicationGroupId']}"),
                        name=rg["ReplicationGroupId"],
                        asset_type=AssetType.CACHE_CLUSTER,
                        metadata={
                            "engine": rg.get("Engine", "redis"),
                            "status": rg.get("Status"),
                            "members": members,
                            "security_groups": sgs,
                            "transit_encryption": rg.get("TransitEncryptionEnabled"),
                            "at_rest_encryption": rg.get("AtRestEncryptionEnabled"),
                            "auth_token_enabled": rg.get("AuthTokenEnabled"),
                            "kms_key_id": rg.get("KmsKeyId"),
                        },
                        relations=[rel(rg.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")],
                        aliases=[
                            rg["ReplicationGroupId"],
                            *members,
                            *(nodes.get(m, {}).get("ARN") or self._arn("elasticache", f"cluster:{m}") for m in members),
                        ],
                    )
                )
            for cid, cc in nodes.items():
                if cid in grouped:
                    continue
                assets.append(
                    self._asset(
                        arn=cc.get("ARN") or self._arn("elasticache", f"cluster:{cid}"),
                        name=cid,
                        asset_type=AssetType.CACHE_CLUSTER,
                        metadata={
                            "engine": cc.get("Engine"),
                            "engine_version": cc.get("EngineVersion"),
                            "node_type": cc.get("CacheNodeType"),
                            "status": cc.get("CacheClusterStatus"),
                            "security_groups": node_sgs(cc),
                            "subnet_group": cc.get("CacheSubnetGroupName"),
                        },
                        aliases=[cid],
                    )
                )
        return assets

    async def _collect_opensearch(self) -> list[CloudAsset]:
        async with self._client("opensearch") as os_client:
            names = [d["DomainName"] for d in (await os_client.list_domain_names()).get("DomainNames", [])]
            assets = []
            for i in range(0, len(names), 5):
                resp = await os_client.describe_domains(DomainNames=names[i : i + 5])
                for d in resp.get("DomainStatusList", []):
                    vpc = d.get("VPCOptions") or {}
                    relations: list[dict | None] = [
                        rel((d.get("EncryptionAtRestOptions") or {}).get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    ]
                    relations += [rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True) for s in vpc.get("SubnetIds", []) or []]
                    for opt in (d.get("LogPublishingOptions") or {}).values():
                        if opt.get("Enabled"):
                            relations.append(rel((opt.get("CloudWatchLogsLogGroupArn") or "").removesuffix(":*"), EdgeType.LOGS_TO, "LOGS_TO"))
                    assets.append(
                        self._asset(
                            arn=d["ARN"],
                            name=d["DomainName"],
                            asset_type=AssetType.SEARCH_DOMAIN,
                            metadata={
                                "engine_version": d.get("EngineVersion"),
                                "in_vpc": bool(vpc),
                                "vpc_id": vpc.get("VPCId"),
                                "security_groups": vpc.get("SecurityGroupIds", []) or [],
                                "endpoint": d.get("Endpoint") or (d.get("Endpoints") or {}).get("vpc"),
                                "fine_grained_access": (d.get("AdvancedSecurityOptions") or {}).get("Enabled"),
                                "node_to_node_encryption": (d.get("NodeToNodeEncryptionOptions") or {}).get("Enabled"),
                            },
                            relations=relations,
                            exposed=not vpc,
                        )
                    )
            return assets

    async def _collect_redshift(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("redshift") as rs:
            async for c in self._paginate(rs, "describe_clusters", "Clusters"):
                cid = c["ClusterIdentifier"]
                relations: list[dict | None] = [rel(c.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")]
                relations += [rel(r.get("IamRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON") for r in c.get("IamRoles", []) or []]
                assets.append(
                    self._asset(
                        arn=c.get("ClusterNamespaceArn") or self._arn("redshift", f"cluster:{cid}"),
                        name=cid,
                        asset_type=AssetType.DATA_WAREHOUSE,
                        tags=c.get("Tags"),
                        metadata={
                            "node_type": c.get("NodeType"),
                            "nodes": c.get("NumberOfNodes"),
                            "encrypted": c.get("Encrypted"),
                            "publicly_accessible": c.get("PubliclyAccessible"),
                            "vpc_id": c.get("VpcId"),
                            "security_groups": [g.get("VpcSecurityGroupId") for g in c.get("VpcSecurityGroups", []) or []],
                            "endpoint": (c.get("Endpoint") or {}).get("Address"),
                        },
                        relations=relations,
                        exposed=bool(c.get("PubliclyAccessible")),
                        aliases=[cid, self._arn("redshift", f"cluster:{cid}")],
                    )
                )
        return assets

    # ------------------------------------------------------------------
    # DNS (global)
    # ------------------------------------------------------------------

    async def _collect_route53(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("route53", region="us-east-1") as r53:
            zones = [z async for z in self._paginate(r53, "list_hosted_zones", "HostedZones")]
            for z in zones:
                zone_id = z["Id"].rsplit("/", 1)[-1]
                zone_arn = f"arn:aws:route53:::hostedzone/{zone_id}"
                private = bool((z.get("Config") or {}).get("PrivateZone"))
                zone_rel: list[dict | None] = []
                if private:
                    try:
                        detail = await r53.get_hosted_zone(Id=zone_id)
                        zone_rel = [rel(v.get("VPCId"), EdgeType.ATTACHED_TO, "DNS_RESOLVED", description="private zone association")
                                    for v in detail.get("VPCs", []) or []]
                    except Exception as exc:
                        logger.debug("Private zone VPC lookup failed: %s", exc)
                assets.append(
                    self._asset(
                        arn=zone_arn,
                        name=z["Name"].rstrip("."),
                        asset_type=AssetType.DNS_ZONE,
                        region="global",
                        metadata={"zone_id": zone_id, "private": private, "record_count": z.get("ResourceRecordSetCount")},
                        relations=zone_rel,
                        aliases=[zone_id],
                    )
                )
                count = 0
                try:
                    async for rr in self._paginate(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zone_id):
                        if rr.get("Type") not in _DNS_RECORD_TYPES:
                            continue
                        count += 1
                        if count > _MAX_RECORDS_PER_ZONE:
                            logger.warning("Route 53 zone %s truncated at %d records", z["Name"], _MAX_RECORDS_PER_ZONE)
                            break
                        alias = rr.get("AliasTarget") or {}
                        values = [r.get("Value", "") for r in rr.get("ResourceRecords", []) or []]
                        targets = [_dns(alias.get("DNSName"))] if alias else [_dns(v) if rr["Type"] == "CNAME" else v for v in values]
                        name = _dns(rr["Name"])
                        relations: list[dict | None] = [rel(zone_arn, EdgeType.CONTAINS, reverse=True)]
                        relations += [rel(t, EdgeType.ROUTE, "DNS_RESOLVED") for t in targets]
                        set_id = rr.get("SetIdentifier")
                        assets.append(
                            self._asset(
                                arn=f"{zone_arn}/{rr['Type']}/{name}" + (f"/{set_id}" if set_id else ""),
                                name=name,
                                asset_type=AssetType.DNS_RECORD,
                                region="global",
                                metadata={
                                    "record_type": rr["Type"],
                                    "alias": bool(alias),
                                    "values": targets,
                                    "private_zone": private,
                                    "routing_policy": "weighted" if "Weight" in rr else ("latency" if "Region" in rr else "simple"),
                                },
                                relations=relations,
                                exposed=not private,
                            )
                        )
                except Exception as exc:
                    logger.debug("Record listing failed for %s: %s", z["Name"], exc)
        return assets

    # ------------------------------------------------------------------
    # Deployment and operations
    # ------------------------------------------------------------------

    async def _collect_cloudformation(self) -> list[CloudAsset]:
        async with self._client("cloudformation") as cfn:
            stacks = [s async for s in self._paginate(cfn, "describe_stacks", "Stacks")]

            async def detail(stack: dict) -> CloudAsset:
                relations: list[dict | None] = [
                    rel(stack.get("RoleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="stack service role"),
                    rel(stack.get("ParentId"), EdgeType.MANAGES, "OWNED_BY", reverse=True, description="nested stack"),
                ]
                types: dict[str, int] = {}
                if self._stack_resources:
                    async for r in self._paginate(cfn, "list_stack_resources", "StackResourceSummaries", StackName=stack["StackId"]):
                        rtype = r.get("ResourceType", "")
                        types[rtype] = types.get(rtype, 0) + 1
                        physical = r.get("PhysicalResourceId")
                        if physical and rtype != "AWS::CloudFormation::Stack":
                            relations.append(rel(physical, EdgeType.MANAGES, "OWNED_BY",
                                                 logical_id=r.get("LogicalResourceId"), resource_type=rtype))
                return self._asset(
                    arn=stack["StackId"],
                    name=stack["StackName"],
                    asset_type=AssetType.IAC_STACK,
                    tags=stack.get("Tags"),
                    metadata={
                        "status": stack.get("StackStatus"),
                        "drift_status": (stack.get("DriftInformation") or {}).get("StackDriftStatus"),
                        "termination_protection": stack.get("EnableTerminationProtection"),
                        "created": str(stack.get("CreationTime", "")),
                        "last_updated": str(stack.get("LastUpdatedTime", "")),
                        "parent_stack": stack.get("ParentId"),
                        "root_stack": stack.get("RootId"),
                        "stack_set": stack["StackName"].startswith("StackSet-"),
                        "control_tower": "AWSControlTower" in stack["StackName"],
                        "resource_types": types,
                    },
                    relations=relations,
                    aliases=[stack["StackName"]],
                )

            results = await gather_limited([lambda s=s: detail(s) for s in stacks], limit=4)
            return [a for a in results if a]

    async def _collect_log_groups(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("logs") as logs:
            async for g in self._paginate(logs, "describe_log_groups", "logGroups"):
                arn = g.get("logGroupArn") or (g.get("arn") or "").removesuffix(":*")
                assets.append(
                    self._asset(
                        arn=arn,
                        name=g["logGroupName"],
                        asset_type=AssetType.LOG_GROUP,
                        metadata={
                            "retention_days": g.get("retentionInDays"),
                            "stored_bytes": g.get("storedBytes"),
                            "kms_key_id": g.get("kmsKeyId"),
                            "log_class": g.get("logGroupClass"),
                        },
                        relations=[rel(g.get("kmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")],
                        aliases=[g.get("arn"), self._arn("logs", f"log-group:{g['logGroupName']}")],
                    )
                )
        return assets

    async def _collect_acm(self) -> list[CloudAsset]:
        async with self._client("acm") as acm:
            # Without Includes.keyTypes only RSA_2048 certificates are listed.
            certs = [
                c
                async for c in self._paginate(
                    acm,
                    "list_certificates",
                    "CertificateSummaryList",
                    Includes={"keyTypes": _ACM_KEY_TYPES},
                )
            ]

            async def detail(c: dict) -> CloudAsset:
                cert = (await acm.describe_certificate(CertificateArn=c["CertificateArn"]))["Certificate"]
                return self._asset(
                    arn=cert["CertificateArn"],
                    name=cert.get("DomainName", ""),
                    asset_type=AssetType.CERTIFICATE,
                    metadata={
                        "status": cert.get("Status"),
                        "type": cert.get("Type"),
                        "not_after": str(cert.get("NotAfter", "")),
                        "renewal_eligibility": cert.get("RenewalEligibility"),
                        "key_algorithm": cert.get("KeyAlgorithm"),
                        "in_use_by": cert.get("InUseBy", []),
                        "subject_alternative_names": cert.get("SubjectAlternativeNames", [])[:20],
                    },
                    relations=[
                        rel(u, EdgeType.REFERENCES, "CERTIFICATE_SECURES", reverse=True)
                        for u in cert.get("InUseBy", []) or []
                    ],
                )

            results = await gather_limited([lambda c=c: detail(c) for c in certs])
            return [a for a in results if a]
