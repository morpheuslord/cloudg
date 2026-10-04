"""Load balancing: ALB/NLB listeners + certificates + access logs, target
groups -> registered targets, classic ELBs -> instances."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, gather_limited, rel
from cloudg.inventory.aws_services.platform.dns_iac_ops import _dns
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split


def _lb_metadata(lb: dict, listeners: list[dict], attrs: dict[str, str]) -> dict[str, Any]:
    return {
        "type": lb.get("Type"),
        "scheme": lb.get("Scheme"),
        "vpc_id": lb.get("VpcId"),
        "state": (lb.get("State") or {}).get("Code"),
        "dns_name": lb.get("DNSName"),
        "security_groups": lb.get("SecurityGroups", []),
        "listeners": listeners,
        "deletion_protection": attrs.get("deletion_protection.enabled") == "true",
        "drops_invalid_headers": attrs.get("routing.http.drop_invalid_header_fields.enabled")
        == "true",
    }


class LoadBalancingCollectorsMixin(AWSServiceMixin):
    # ------------------------------------------------------------------
    # ELBv2 (overrides the shallow base collector)
    # ------------------------------------------------------------------

    async def _collect_elbv2(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("elbv2") as elb:
            lbs = [
                lb async for lb in self._paginate(elb, "describe_load_balancers", "LoadBalancers")
            ]
            results = await gather_limited(
                [lambda lb=lb: self._elbv2_lb_asset(elb, lb) for lb in lbs]
            )
            assets.extend(a for a in results if a)

            tgs = [tg async for tg in self._paginate(elb, "describe_target_groups", "TargetGroups")]
            results = await gather_limited(
                [lambda tg=tg: self._elbv2_tg_asset(elb, tg) for tg in tgs]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _elbv2_listeners(
        self, elb: Any, arn: str, relations: list[dict | None]
    ) -> list[dict]:
        """Listener summaries; each listener certificate becomes a relation."""
        listeners = []
        async for listener in self._paginate(
            elb, "describe_listeners", "Listeners", LoadBalancerArn=arn
        ):
            listeners.append(
                {
                    "port": listener.get("Port"),
                    "protocol": listener.get("Protocol"),
                    "ssl_policy": listener.get("SslPolicy"),
                }
            )
            for cert in listener.get("Certificates", []) or []:
                relations.append(
                    rel(cert.get("CertificateArn"), EdgeType.REFERENCES, "CERTIFICATE_SECURES")
                )
        return listeners

    async def _elbv2_lb_attributes(self, elb: Any, arn: str) -> dict[str, str]:
        try:
            resp = await elb.describe_load_balancer_attributes(LoadBalancerArn=arn)
            return {a["Key"]: a["Value"] for a in resp.get("Attributes", [])}
        except Exception as exc:
            logger.debug("LB attributes unavailable for %s: %s", arn, exc)
            return {}

    async def _elbv2_lb_asset(self, elb: Any, lb: dict) -> CloudAsset:
        arn = lb["LoadBalancerArn"]
        relations: list[dict | None] = []
        listeners = await self._elbv2_listeners(elb, arn, relations)
        attrs = await self._elbv2_lb_attributes(elb, arn)
        if attrs.get("access_logs.s3.enabled") == "true" and attrs.get("access_logs.s3.bucket"):
            relations.append(
                rel(
                    f"arn:aws:s3:::{attrs['access_logs.s3.bucket']}",
                    EdgeType.LOGS_TO,
                    "LOGS_TO",
                )
            )
        for az in lb.get("AvailabilityZones", []) or []:
            relations.append(
                rel(az.get("SubnetId"), EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
            )
        return self._asset(
            arn=arn,
            name=lb.get("LoadBalancerName", ""),
            asset_type=AssetType.LOAD_BALANCER,
            metadata=_lb_metadata(lb, listeners, attrs),
            relations=relations,
            raw=lb,
            exposed=lb.get("Scheme") == "internet-facing",
            aliases=[_dns(lb.get("DNSName"))],
        )

    async def _elbv2_tg_asset(self, elb: Any, tg: dict) -> CloudAsset:
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
                targets.append(
                    {"id": tid, "port": (desc.get("Target") or {}).get("Port"), "state": state}
                )
                relations.append(
                    rel(tid, EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE", health=state)
                )
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

    # ------------------------------------------------------------------
    # Classic ELB
    # ------------------------------------------------------------------

    async def _collect_elb_classic(self) -> list[CloudAsset]:
        async with self._client("elb") as elb:
            out = []
            async for lb in self._paginate(
                elb, "describe_load_balancers", "LoadBalancerDescriptions"
            ):
                name = lb.get("LoadBalancerName", "")
                relations = [
                    rel(i.get("InstanceId"), EdgeType.LOAD_BALANCER_TARGET, "LB_TARGETS_INSTANCE")
                    for i in lb.get("Instances", []) or []
                ]
                relations += [
                    rel(s, EdgeType.CONTAINS, "SUBNET_CONTAINS_INSTANCE", reverse=True)
                    for s in lb.get("Subnets", []) or []
                ]
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
