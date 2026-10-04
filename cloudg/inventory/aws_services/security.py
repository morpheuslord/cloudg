"""Security services and scanners: what protects and watches the estate.

Each service is mapped per account and region. When a service is not
deployed, a placeholder asset with ``metadata.enabled = False`` is emitted
so detection and scanning gaps are visible on the map and in the summary.

- GuardDuty detectors (features, delegated admin) -> MONITORS account
- Security Hub (standards, product integrations, admin) -> aggregates the
  GuardDuty/Inspector/Macie deployments it ingests from
- Inspector2 (per resource type) -> MONITORS every covered EC2 instance,
  ECR repository and Lambda function, with scan status
- Macie, AWS Config (recorder + delivery channel), IAM Access Analyzer,
  Detective
- WAFv2 web ACLs -> PROTECTS ALBs, API Gateway stages, CloudFront
- Network Firewall -> PROTECTS VPC / subnets
- Shield Advanced protections -> PROTECTS resources
- CloudTrail trails -> LOGS_TO S3 / CloudWatch Logs, MONITORS account
"""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    error_code,
    rel,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

_NOT_ENABLED_CODES = {
    "InvalidAccessException",
    "ResourceNotFoundException",
    "AccessDeniedException",
    "BadRequestException",
    "NoSuchConfigurationRecorderException",
}
_MAX_COVERAGE = 10000
_WAF_RESOURCE_TYPES = (
    "APPLICATION_LOAD_BALANCER",
    "API_GATEWAY",
    "APPSYNC",
    "COGNITO_USER_POOL",
    "APP_RUNNER_SERVICE",
    "VERIFIED_ACCESS_INSTANCE",
    "AMPLIFY",
)


def _disabled_reason(exc: BaseException) -> str:
    return (
        "not enabled or access denied"
        if error_code(exc) == "AccessDeniedException"
        else "not enabled"
    )


def _coverage_target(resource_id: str) -> str:
    """Inspector reports ECR images as repo/sha256 ARNs: link to the repository."""
    if ":repository/" in resource_id and "/sha256:" in resource_id:
        return resource_id.split("/sha256:", 1)[0]
    return resource_id


class SecurityCollectorsMixin(AWSServiceMixin):
    _is_primary_region: bool = True

    async def _collect_guardduty(self) -> list[CloudAsset]:
        async with self._client("guardduty") as gd:
            ids = [d async for d in self._paginate(gd, "list_detectors", "DetectorIds")]
            if not ids:
                return [self._disabled_asset("guardduty", AssetType.THREAT_DETECTOR, "GuardDuty")]
            assets = []
            for det_id in ids:
                d = await gd.get_detector(DetectorId=det_id)
                admin = None
                try:
                    admin = (
                        (await gd.get_administrator_account(DetectorId=det_id)).get("Administrator")
                        or {}
                    ).get("AccountId")
                except Exception as exc:
                    logger.debug("GuardDuty admin lookup failed: %s", exc)
                features = {f.get("Name"): f.get("Status") for f in d.get("Features", []) or []}
                assets.append(
                    self._asset(
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
                            rel(
                                self._account_ref(),
                                EdgeType.MONITORS,
                                "MONITORED_BY",
                                description="threat detection",
                            ),
                            rel(
                                f"arn:aws:iam::{admin}:root" if admin else None,
                                EdgeType.MONITORS,
                                "MONITORED_BY",
                                reverse=True,
                                description="GuardDuty administrator",
                            ),
                        ],
                        aliases=[self._security_alias("guardduty")],
                    )
                )
            return assets

    async def _collect_securityhub(self) -> list[CloudAsset]:
        async with self._client("securityhub") as sh:
            try:
                hub = await sh.describe_hub()
            except Exception as exc:
                if error_code(exc) in _NOT_ENABLED_CODES:
                    return [
                        self._disabled_asset(
                            "securityhub",
                            AssetType.SECURITY_HUB,
                            "Security Hub",
                            _disabled_reason(exc),
                        )
                    ]
                raise
            standards: list[str] = []
            try:
                async for s in self._paginate(
                    sh, "get_enabled_standards", "StandardsSubscriptions"
                ):
                    standards.append(s.get("StandardsArn", "").split("/standards/", 1)[-1])
            except Exception as exc:
                logger.debug("Security Hub standards unavailable: %s", exc)
            products: list[str] = []
            try:
                async for p in self._paginate(
                    sh, "list_enabled_products_for_import", "ProductSubscriptions"
                ):
                    products.append(p)
            except Exception as exc:
                logger.debug("Security Hub products unavailable: %s", exc)
            admin = None
            try:
                admin = ((await sh.get_administrator_account()).get("Administrator") or {}).get(
                    "AccountId"
                )
            except Exception as exc:
                logger.debug("Security Hub admin lookup failed: %s", exc)
            integrations = sorted({p.rsplit("/", 1)[-1] for p in products})
            relations = [
                rel(
                    self._account_ref(),
                    EdgeType.MONITORS,
                    "MONITORED_BY",
                    description="posture management",
                ),
                rel(
                    f"arn:aws:iam::{admin}:root" if admin else None,
                    EdgeType.MONITORS,
                    "MONITORED_BY",
                    reverse=True,
                    description="Security Hub administrator",
                ),
            ]
            for svc in ("guardduty", "inspector", "macie", "access-analyzer", "config"):
                if svc in integrations or svc.replace("-", "") in integrations:
                    alias_svc = {
                        "inspector": "inspector2",
                        "access-analyzer": "accessanalyzer",
                    }.get(svc, svc)
                    relations.append(
                        rel(
                            self._security_alias(alias_svc),
                            EdgeType.MONITORS,
                            "READS_FROM",
                            description=f"ingests {svc} findings",
                        )
                    )
            return [
                self._asset(
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
            ]

    async def _collect_inspector2(self) -> list[CloudAsset]:
        async with self._client("inspector2") as insp:
            resp = await insp.batch_get_account_status(
                accountIds=[self._account_id] if self._account_id else []
            )
            accounts = resp.get("accounts", [])
            if not accounts:
                return [
                    self._disabled_asset("inspector2", AssetType.VULNERABILITY_SCANNER, "Inspector")
                ]
            acct = accounts[0]
            resource_state = {
                k: (v or {}).get("status") for k, v in (acct.get("resourceState") or {}).items()
            }
            enabled = (acct.get("state") or {}).get("status") == "ENABLED" or any(
                s == "ENABLED" for s in resource_state.values()
            )
            if not enabled:
                return [
                    self._disabled_asset("inspector2", AssetType.VULNERABILITY_SCANNER, "Inspector")
                ]

            relations: list[dict | None] = []
            status_counts: dict[str, int] = {}
            covered = 0
            try:
                async for res in self._paginate(insp, "list_coverage", "coveredResources"):
                    covered += 1
                    if covered > _MAX_COVERAGE:
                        logger.warning(
                            "Inspector coverage truncated at %d resources", _MAX_COVERAGE
                        )
                        break
                    status = (res.get("scanStatus") or {}).get("statusCode", "UNKNOWN")
                    status_counts[status] = status_counts.get(status, 0) + 1
                    relations.append(
                        rel(
                            _coverage_target(res.get("resourceId", "")),
                            EdgeType.MONITORS,
                            "MONITORED_BY",
                            description=f"{res.get('scanType')} scan",
                            scan_status=status,
                            reason=(res.get("scanStatus") or {}).get("reason"),
                            resource_type=res.get("resourceType"),
                        )
                    )
            except Exception as exc:
                logger.debug("Inspector coverage listing failed: %s", exc)
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

    async def _collect_macie(self) -> list[CloudAsset]:
        async with self._client("macie2") as macie:
            try:
                session = await macie.get_macie_session()
            except Exception as exc:
                if error_code(exc) in _NOT_ENABLED_CODES:
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
                        rel(
                            self._account_ref(),
                            EdgeType.MONITORS,
                            "MONITORED_BY",
                            description="sensitive data discovery",
                        ),
                        rel(session.get("serviceRole"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                    ],
                    aliases=[self._security_alias("macie")],
                )
            ]

    async def _collect_config(self) -> list[CloudAsset]:
        async with self._client("config") as cfg:
            recorders = (await cfg.describe_configuration_recorders()).get(
                "ConfigurationRecorders", []
            )
            if not recorders:
                return [self._disabled_asset("config", AssetType.CONFIG_RECORDER, "AWS Config")]
            statuses = {
                s.get("name"): s
                for s in (await cfg.describe_configuration_recorder_status()).get(
                    "ConfigurationRecordersStatus", []
                )
            }
            channels = (await cfg.describe_delivery_channels()).get("DeliveryChannels", [])
            rule_names: list[str] = []
            try:
                async for r in self._paginate(cfg, "describe_config_rules", "ConfigRules"):
                    rule_names.append(r.get("ConfigRuleName", ""))
            except Exception as exc:
                logger.debug("Config rule listing failed: %s", exc)
            aggregators: list[str] = []
            try:
                async for a in self._paginate(
                    cfg, "describe_configuration_aggregators", "ConfigurationAggregators"
                ):
                    aggregators.append(a.get("ConfigurationAggregatorName", ""))
            except Exception as exc:
                logger.debug("Config aggregator listing failed: %s", exc)

            assets = []
            for rec in recorders:
                name = rec.get("name", "default")
                group = rec.get("recordingGroup") or {}
                status = statuses.get(name, {})
                relations: list[dict | None] = [
                    rel(
                        self._account_ref(),
                        EdgeType.MONITORS,
                        "MONITORED_BY",
                        description="configuration recording",
                    ),
                    rel(rec.get("roleARN"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                ]
                for ch in channels:
                    if ch.get("s3BucketName"):
                        relations.append(
                            rel(f"arn:aws:s3:::{ch['s3BucketName']}", EdgeType.LOGS_TO, "LOGS_TO")
                        )
                    relations.append(rel(ch.get("snsTopicARN"), EdgeType.LOGS_TO, "STREAMS_TO"))
                    relations.append(
                        rel(ch.get("s3KmsKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
                    )
                assets.append(
                    self._asset(
                        arn=rec.get("arn") or self._arn("config", f"config-recorder/{name}"),
                        name=f"config-{name}",
                        asset_type=AssetType.CONFIG_RECORDER,
                        metadata={
                            "security_service": "config",
                            "enabled": bool(status.get("recording")),
                            "recording": status.get("recording"),
                            "last_status": status.get("lastStatus"),
                            "all_supported": group.get("allSupported"),
                            "include_global_resources": group.get("includeGlobalResourceTypes"),
                            "rule_count": len(rule_names),
                            "rules": rule_names[:100],
                            "aggregators": aggregators,
                        },
                        relations=relations,
                        aliases=[self._security_alias("config")],
                    )
                )
            return assets

    async def _collect_access_analyzer(self) -> list[CloudAsset]:
        async with self._client("accessanalyzer") as aa:
            analyzers = [a async for a in self._paginate(aa, "list_analyzers", "analyzers")]
            if not analyzers:
                return [
                    self._disabled_asset(
                        "accessanalyzer", AssetType.ACCESS_ANALYZER, "IAM Access Analyzer"
                    )
                ]
            return [
                self._asset(
                    arn=a["arn"],
                    name=a.get("name", ""),
                    asset_type=AssetType.ACCESS_ANALYZER,
                    tags=a.get("tags"),
                    metadata={
                        "security_service": "accessanalyzer",
                        "enabled": a.get("status") == "ACTIVE",
                        "type": a.get("type"),
                        "status": a.get("status"),
                    },
                    relations=[
                        rel(
                            self._account_ref(),
                            EdgeType.MONITORS,
                            "MONITORED_BY",
                            description=f"{a.get('type')} analyzer",
                        )
                    ],
                    aliases=[self._security_alias("accessanalyzer")],
                )
                for a in analyzers
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
                    relations=[
                        rel(
                            self._account_ref(),
                            EdgeType.MONITORS,
                            "MONITORED_BY",
                            description="investigation graph",
                        )
                    ],
                    aliases=[self._security_alias("detective")],
                )
                for g in graphs
            ]

    async def _waf_acls(self, scope: str, region: str) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("wafv2", region=region) as waf:
            marker = None
            acls: list[dict] = []
            while True:
                kwargs: dict[str, Any] = {"Scope": scope, "Limit": 100}
                if marker:
                    kwargs["NextMarker"] = marker
                resp = await waf.list_web_acls(**kwargs)
                acls.extend(resp.get("WebACLs", []))
                marker = resp.get("NextMarker")
                if not marker or not resp.get("WebACLs"):
                    break
            for acl in acls:
                relations: list[dict | None] = []
                rules: list[str] = []
                default_action = None
                try:
                    detail = (await waf.get_web_acl(Name=acl["Name"], Scope=scope, Id=acl["Id"]))[
                        "WebACL"
                    ]
                    default_action = next(iter(detail.get("DefaultAction") or {}), None)
                    for r in detail.get("Rules", []) or []:
                        managed = (
                            (r.get("Statement") or {}).get("ManagedRuleGroupStatement") or {}
                        ).get("Name")
                        rules.append(managed or r.get("Name", ""))
                except Exception as exc:
                    logger.debug("get_web_acl failed for %s: %s", acl.get("Name"), exc)
                if scope == "REGIONAL":
                    for rtype in _WAF_RESOURCE_TYPES:
                        try:
                            res = await waf.list_resources_for_web_acl(
                                WebACLArn=acl["ARN"], ResourceType=rtype
                            )
                            for arn in res.get("ResourceArns", []):
                                target = (
                                    arn.split("/stages/", 1)[0] if rtype == "API_GATEWAY" else arn
                                )
                                relations.append(rel(target, EdgeType.PROTECTS, "PROTECTED_BY_WAF"))
                        except Exception as exc:
                            logger.debug("WAF resources (%s) unavailable: %s", rtype, exc)
                assets.append(
                    self._asset(
                        arn=acl["ARN"],
                        name=acl["Name"],
                        asset_type=AssetType.WAF_WEB_ACL,
                        region="global" if scope == "CLOUDFRONT" else region,
                        metadata={
                            "security_service": "wafv2",
                            "enabled": True,
                            "scope": scope,
                            "default_action": default_action,
                            "rules": rules,
                        },
                        relations=relations,
                        aliases=[acl.get("Id")],
                    )
                )
        return assets

    async def _collect_wafv2(self) -> list[CloudAsset]:
        assets = await self._waf_acls("REGIONAL", self._region)
        if self._is_primary_region:
            try:
                assets.extend(await self._waf_acls("CLOUDFRONT", "us-east-1"))
            except Exception as exc:
                logger.debug("CloudFront-scope WAF listing failed: %s", exc)
        return assets

    async def _collect_network_firewall(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("network-firewall") as nfw:
            firewalls = [f async for f in self._paginate(nfw, "list_firewalls", "Firewalls")]
            for fw in firewalls:
                d = await nfw.describe_firewall(FirewallArn=fw["FirewallArn"])
                firewall = d.get("Firewall") or {}
                relations: list[dict | None] = [
                    rel(firewall.get("VpcId"), EdgeType.PROTECTS, "PROTECTED_BY_NACL"),
                    rel(
                        firewall.get("TransitGatewayId"),
                        EdgeType.PROTECTS,
                        "PROTECTED_BY_NACL",
                        description="transit gateway attached firewall",
                    ),
                    rel(firewall.get("FirewallPolicyArn"), EdgeType.REFERENCES, "DEPENDS_ON"),
                ]
                for m in firewall.get("SubnetMappings", []) or []:
                    relations.append(
                        rel(
                            m.get("SubnetId"),
                            EdgeType.CONTAINS,
                            "SUBNET_CONTAINS_INSTANCE",
                            reverse=True,
                        )
                    )
                assets.append(
                    self._asset(
                        arn=fw["FirewallArn"],
                        name=fw.get("FirewallName", ""),
                        asset_type=AssetType.NETWORK_FIREWALL,
                        tags=firewall.get("Tags"),
                        metadata={
                            "security_service": "network-firewall",
                            "enabled": True,
                            "vpc_id": firewall.get("VpcId"),
                            "policy_arn": firewall.get("FirewallPolicyArn"),
                            "delete_protection": firewall.get("DeleteProtection"),
                        },
                        relations=relations,
                    )
                )
        return assets

    async def _collect_shield(self) -> list[CloudAsset]:
        async with self._client("shield", region="us-east-1") as shield:
            try:
                sub = (await shield.describe_subscription()).get("Subscription") or {}
            except Exception as exc:
                if error_code(exc) in _NOT_ENABLED_CODES:
                    return []  # Shield Standard only: nothing to map
                raise
            relations = [
                rel(
                    p.get("ResourceArn"),
                    EdgeType.PROTECTS,
                    "PROTECTED_BY_WAF",
                    description=f"Shield protection {p.get('Name')}",
                )
                async for p in self._paginate(shield, "list_protections", "Protections")
            ]
            return [
                self._asset(
                    arn=sub.get("SubscriptionArn")
                    or f"arn:aws:shield::{self._account_id}:subscription",
                    name="shield-advanced",
                    asset_type=AssetType.DDOS_PROTECTION,
                    region="global",
                    metadata={
                        "security_service": "shield",
                        "enabled": True,
                        "auto_renew": sub.get("AutoRenew"),
                        "proactive_engagement": sub.get("ProactiveEngagementStatus"),
                        "protections": len(relations),
                    },
                    relations=relations,
                )
            ]

    async def _collect_cloudtrail(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("cloudtrail") as ct:
            # Shadow trails include multi-region trails homed elsewhere and the
            # organization trail of the management account, so member
            # accounts are not reported as unaudited. The same trail seen
            # from several regions is merged by ARN in the mapper.
            trails = (await ct.describe_trails(includeShadowTrails=True)).get("trailList", [])
            if not trails:
                return [
                    self._disabled_asset(
                        "cloudtrail",
                        AssetType.CLOUDTRAIL,
                        "CloudTrail",
                        "no trail covers this region",
                    )
                ]
            for t in trails:
                home = t.get("HomeRegion", self._region)
                if (
                    home != self._region
                    and not t.get("IsMultiRegionTrail")
                    and not t.get("IsOrganizationTrail")
                ):
                    continue
                logging_on = None
                if home == self._region:
                    try:
                        logging_on = (await ct.get_trail_status(Name=t["TrailARN"])).get(
                            "IsLogging"
                        )
                    except Exception as exc:
                        logger.debug("Trail status failed: %s", exc)
                else:
                    logging_on = True  # visible as a shadow trail: it is delivering here
                relations = [
                    rel(
                        self._account_ref(),
                        EdgeType.MONITORS,
                        "MONITORED_BY",
                        description="API audit logging",
                        organization_trail=t.get("IsOrganizationTrail"),
                    ),
                    rel(
                        f"arn:aws:s3:::{t['S3BucketName']}" if t.get("S3BucketName") else None,
                        EdgeType.LOGS_TO,
                        "LOGS_TO",
                    ),
                    rel(
                        (t.get("CloudWatchLogsLogGroupArn") or "").removesuffix(":*"),
                        EdgeType.LOGS_TO,
                        "LOGS_TO",
                    ),
                    rel(t.get("CloudWatchLogsRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                    rel(t.get("KmsKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(t.get("SnsTopicARN"), EdgeType.LOGS_TO, "STREAMS_TO"),
                ]
                assets.append(
                    self._asset(
                        arn=t["TrailARN"],
                        name=t.get("Name", ""),
                        asset_type=AssetType.CLOUDTRAIL,
                        region=home,
                        metadata={
                            "security_service": "cloudtrail",
                            "enabled": bool(logging_on),
                            "is_logging": logging_on,
                            "multi_region": t.get("IsMultiRegionTrail"),
                            "organization_trail": t.get("IsOrganizationTrail"),
                            "log_file_validation": t.get("LogFileValidationEnabled"),
                            "s3_bucket": t.get("S3BucketName"),
                            "kms_key_id": t.get("KmsKeyId"),
                        },
                        relations=relations,
                        aliases=[self._security_alias("cloudtrail")],
                    )
                )
        return assets
