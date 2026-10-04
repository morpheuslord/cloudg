"""DNS, deployment and operations: Route 53 zones and records (-> what they
resolve to), CloudFormation stacks (-> every resource they manage),
CloudWatch log groups and ACM certificates (-> what uses them)."""

from __future__ import annotations

import logging
from typing import Any, AsyncIterator

from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

_MAX_RECORDS_PER_ZONE = 2000
_ACM_KEY_TYPES = [
    "RSA_1024",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "EC_prime256v1",
    "EC_secp384r1",
    "EC_secp521r1",
]
_DNS_RECORD_TYPES = {"A", "AAAA", "CNAME"}

logger = logging.getLogger(__package__)  # the package logger, as before the split


def _dns(name: str | None) -> str:
    """Normalise a DNS name for matching (lowercase, no trailing dot/dualstack)."""
    if not name:
        return ""
    n = name.lower().rstrip(".")
    return n[len("dualstack.") :] if n.startswith("dualstack.") else n


def _record_targets(rr: dict) -> tuple[dict, list[str]]:
    """The alias target and the normalised values a record resolves to."""
    alias = rr.get("AliasTarget") or {}
    if alias:
        return alias, [_dns(alias.get("DNSName"))]
    values = [r.get("Value", "") for r in rr.get("ResourceRecords", []) or []]
    return alias, [_dns(v) if rr["Type"] == "CNAME" else v for v in values]


def _routing_policy(rr: dict) -> str:
    if "Weight" in rr:
        return "weighted"
    return "latency" if "Region" in rr else "simple"


class DnsIacOpsCollectorsMixin(AWSServiceMixin):
    _stack_resources: bool = True

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
                assets.append(await self._route53_zone_asset(r53, z, zone_id, private))
                try:
                    async for record in self._route53_record_assets(r53, z, zone_arn, private):
                        assets.append(record)
                except Exception as exc:
                    logger.debug("Record listing failed for %s: %s", z["Name"], exc)
        return assets

    async def _route53_zone_asset(
        self, r53: Any, z: dict, zone_id: str, private: bool
    ) -> CloudAsset:
        zone_rel: list[dict | None] = []
        if private:
            try:
                detail = await r53.get_hosted_zone(Id=zone_id)
                zone_rel = [
                    rel(
                        v.get("VPCId"),
                        EdgeType.ATTACHED_TO,
                        "DNS_RESOLVED",
                        description="private zone association",
                    )
                    for v in detail.get("VPCs", []) or []
                ]
            except Exception as exc:
                logger.debug("Private zone VPC lookup failed: %s", exc)
        return self._asset(
            arn=f"arn:aws:route53:::hostedzone/{zone_id}",
            name=z["Name"].rstrip("."),
            asset_type=AssetType.DNS_ZONE,
            region="global",
            metadata={
                "zone_id": zone_id,
                "private": private,
                "record_count": z.get("ResourceRecordSetCount"),
            },
            relations=zone_rel,
            aliases=[zone_id],
        )

    async def _route53_record_assets(
        self, r53: Any, z: dict, zone_arn: str, private: bool
    ) -> AsyncIterator[CloudAsset]:
        """A, AAAA and CNAME records of one zone, capped per zone."""
        zone_id = zone_arn.rsplit("/", 1)[-1]
        count = 0
        async for rr in self._paginate(
            r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=zone_id
        ):
            if rr.get("Type") not in _DNS_RECORD_TYPES:
                continue
            count += 1
            if count > _MAX_RECORDS_PER_ZONE:
                logger.warning(
                    "Route 53 zone %s truncated at %d records",
                    z["Name"],
                    _MAX_RECORDS_PER_ZONE,
                )
                break
            yield self._route53_record_asset(rr, zone_arn, private)

    def _route53_record_asset(self, rr: dict, zone_arn: str, private: bool) -> CloudAsset:
        alias, targets = _record_targets(rr)
        name = _dns(rr["Name"])
        relations: list[dict | None] = [rel(zone_arn, EdgeType.CONTAINS, reverse=True)]
        relations += [rel(t, EdgeType.ROUTE, "DNS_RESOLVED") for t in targets]
        set_id = rr.get("SetIdentifier")
        return self._asset(
            arn=f"{zone_arn}/{rr['Type']}/{name}" + (f"/{set_id}" if set_id else ""),
            name=name,
            asset_type=AssetType.DNS_RECORD,
            region="global",
            metadata={
                "record_type": rr["Type"],
                "alias": bool(alias),
                "values": targets,
                "private_zone": private,
                "routing_policy": _routing_policy(rr),
            },
            relations=relations,
            exposed=not private,
        )

    # ------------------------------------------------------------------
    # Deployment and operations
    # ------------------------------------------------------------------

    async def _collect_cloudformation(self) -> list[CloudAsset]:
        async with self._client("cloudformation") as cfn:
            stacks = [s async for s in self._paginate(cfn, "describe_stacks", "Stacks")]
            results = await gather_limited(
                [lambda s=s: self._cfn_stack_asset(cfn, s) for s in stacks], limit=4
            )
            return [a for a in results if a]

    async def _cfn_stack_resources(
        self, cfn: Any, stack: dict, relations: list[dict | None]
    ) -> dict[str, int]:
        """Add an OWNED_BY relation per managed resource; count resource types."""
        types: dict[str, int] = {}
        if not self._stack_resources:
            return types
        async for r in self._paginate(
            cfn,
            "list_stack_resources",
            "StackResourceSummaries",
            StackName=stack["StackId"],
        ):
            rtype = r.get("ResourceType", "")
            types[rtype] = types.get(rtype, 0) + 1
            physical = r.get("PhysicalResourceId")
            if physical and rtype != "AWS::CloudFormation::Stack":
                relations.append(
                    rel(
                        physical,
                        EdgeType.MANAGES,
                        "OWNED_BY",
                        logical_id=r.get("LogicalResourceId"),
                        resource_type=rtype,
                    )
                )
        return types

    async def _cfn_stack_asset(self, cfn: Any, stack: dict) -> CloudAsset:
        relations: list[dict | None] = [
            rel(
                stack.get("RoleARN"),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="stack service role",
            ),
            rel(
                stack.get("ParentId"),
                EdgeType.MANAGES,
                "OWNED_BY",
                reverse=True,
                description="nested stack",
            ),
        ]
        types = await self._cfn_stack_resources(cfn, stack, relations)
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
            results = await gather_limited(
                [lambda c=c: self._acm_cert_asset(acm, c) for c in certs]
            )
            return [a for a in results if a]

    async def _acm_cert_asset(self, acm: Any, c: dict) -> CloudAsset:
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
