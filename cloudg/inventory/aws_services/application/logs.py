"""CloudWatch Logs subscription filters (and account-wide subscription
policies), log destinations, logs resource policies and cross-account
observability (OAM sinks and links)."""

from __future__ import annotations

import json
from typing import Any

from cloudg.inventory.aws_services._base import (
    condition_values,
    error_code,
    gather_limited,
    policy_principals,
    policy_statements,
    rel,
)
from cloudg.inventory.aws_services.application._common import (
    _MAX_LOG_GROUPS_FOR_FILTERS,
    ApplicationBase,
    _arn_account,
    _resource_list,
    _role_rel,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _policy_resource_relations(st: dict) -> list[dict | None]:
    """Concrete log-group resources a logs resource-policy statement names."""
    return [
        rel(res.removesuffix(":*"), EdgeType.REFERENCES, "WRITES_TO", description="policy resource")
        for res in _resource_list(st.get("Resource"))
        if res.startswith("arn:") and "*" not in res.split("log-group:", 1)[-1]
    ]


class LogsCollectorsMixin(ApplicationBase):
    """CloudWatch Logs subscription, destination, resource policy and OAM
    collectors."""

    def _subscription_relations(self, destination: Any, role: Any, label: str) -> list[dict | None]:
        return [
            rel(
                destination,
                EdgeType.INVOKES,
                "STREAMS_TO",
                description=label,
                cross_account=self._cross_account(destination) or None,
            ),
            _role_rel(role, "subscription delivery role"),
        ]

    def _account_subscription_asset(self, pol: dict) -> CloudAsset:
        doc: dict[str, Any] = {}
        try:
            doc = json.loads(pol.get("policyDocument") or "{}")
        except ValueError:
            pass
        name = pol.get("policyName", "")
        account = pol.get("accountId") or self._account_id
        return self._asset(
            arn=f"cloudg:aws:logs:{self._region}:{account}:account-policy/subscription/{name}",
            name=f"account subscription policy {name}",
            asset_type=AssetType.LOG_SINK,
            metadata={
                "service": "logs",
                "kind": "account_subscription_policy",
                "scope": pol.get("scope"),
                "selection_criteria": pol.get("selectionCriteria"),
                "destination_arn": doc.get("DestinationArn"),
                "filter_pattern": doc.get("FilterPattern"),
                "distribution": doc.get("Distribution"),
            },
            relations=self._subscription_relations(
                doc.get("DestinationArn"), doc.get("RoleArn"), "account-wide subscription"
            ),
        )

    def _subscription_filter_asset(self, group: str, f: dict) -> CloudAsset:
        group_arn = self._log_group_arn(group)
        fname = f.get("filterName", "")
        return self._asset(
            arn=f"{group_arn}:subscription-filter:{fname}",
            name=f"{group} -> {fname}",
            asset_type=AssetType.LOG_SINK,
            metadata={
                "service": "logs",
                "kind": "subscription_filter",
                "log_group": group,
                "destination_arn": f.get("destinationArn"),
                "filter_pattern": f.get("filterPattern"),
                "distribution": f.get("distribution"),
            },
            relations=[
                rel(
                    group_arn,
                    EdgeType.INVOKES,
                    "STREAMS_TO",
                    reverse=True,
                    description="subscribed log group",
                ),
                *self._subscription_relations(
                    f.get("destinationArn"), f.get("roleArn"), "subscription destination"
                ),
            ],
        )

    async def _account_subscription_assets(self, logs: Any) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        try:
            async for pol in self._pages(
                logs.describe_account_policies,
                "accountPolicies",
                cursor_param="nextToken",
                policyType="SUBSCRIPTION_FILTER_POLICY",
            ):
                assets.append(self._account_subscription_asset(pol))
        except Exception as exc:
            logger.debug("describe_account_policies failed: %s", exc)
        return assets

    async def _collect_log_subscriptions(self) -> list[CloudAsset]:
        async with self._client("logs") as logs:
            assets = await self._account_subscription_assets(logs)
            groups: list[str] = []
            async for g in self._paginate(logs, "describe_log_groups", "logGroups"):
                groups.append(g["logGroupName"])
                if len(groups) >= _MAX_LOG_GROUPS_FOR_FILTERS:
                    break

            async def filters_for(group: str) -> list[CloudAsset]:
                return [
                    self._subscription_filter_asset(group, f)
                    async for f in self._paginate(
                        logs,
                        "describe_subscription_filters",
                        "subscriptionFilters",
                        logGroupName=group,
                    )
                ]

            results = await gather_limited([lambda g=g: filters_for(g) for g in groups])
            for r in results:
                assets.extend(r or [])
        return assets

    def _log_destination_asset(self, d: dict) -> CloudAsset:
        pol_relations, public = self._app_policy_grants(
            d.get("accessPolicy"), "may subscribe log groups"
        )
        return self._asset(
            arn=d.get("arn") or self._arn("logs", f"destination:{d.get('destinationName')}"),
            name=d.get("destinationName", ""),
            asset_type=AssetType.LOG_SINK,
            metadata={
                "service": "logs",
                "kind": "log_destination",
                "target_arn": d.get("targetArn"),
                "policy_allows_public": public,
                "org_condition": condition_values(
                    next(iter(policy_statements(d.get("accessPolicy"))), {}),
                    "aws:PrincipalOrgID",
                ),
            },
            relations=[
                *self._subscription_relations(
                    d.get("targetArn"), d.get("roleArn"), "destination target"
                ),
                *pol_relations,
            ],
            exposed=public,
        )

    def _logs_resource_policy_asset(self, p: dict) -> CloudAsset:
        name = p.get("policyName", "")
        services: set[str] = set()
        relations: list[dict | None] = []
        for st in policy_statements(p.get("policyDocument")):
            if st.get("Effect") != "Allow":
                continue
            services.update(policy_principals(st).get("Service", []))
            grants, _ = self._app_statement_grants(st, None)
            relations += grants
            relations += _policy_resource_relations(st)
        relations.append(
            rel(
                p.get("resourceArn"),
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="policy attached to",
            )
        )
        return self._asset(
            arn=f"cloudg:aws:logs:{self._region}:{self._account_id}:resource-policy/{name}",
            name=f"logs resource policy {name}",
            asset_type=AssetType.IAM_POLICY,
            metadata={
                "service": "logs",
                "kind": "logs_resource_policy",
                "scope": p.get("policyScope"),
                "service_principals": sorted(services),
            },
            relations=relations,
        )

    async def _collect_log_destinations(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("logs") as logs:
            async for d in self._paginate(logs, "describe_destinations", "destinations"):
                assets.append(self._log_destination_asset(d))
            try:
                async for p in self._paginate(
                    logs, "describe_resource_policies", "resourcePolicies"
                ):
                    assets.append(self._logs_resource_policy_asset(p))
            except Exception as exc:
                logger.debug("describe_resource_policies failed: %s", exc)
        return assets

    # ------------------------------------------------------------------
    # Cross-account observability (OAM)
    # ------------------------------------------------------------------

    async def _oam_sink_asset(self, oam: Any, s: dict) -> CloudAsset:
        relations: list[dict | None] = []
        orgs: list[str] = []
        try:
            pol = await oam.get_sink_policy(SinkIdentifier=s["Arn"])
            for st in policy_statements(pol.get("Policy")):
                if st.get("Effect") != "Allow":
                    continue
                orgs += condition_values(st, "aws:PrincipalOrgID", "aws:PrincipalOrgPaths")
                grants, _ = self._app_statement_grants(st, "source account may link")
                relations += grants
        except Exception as exc:
            if error_code(exc) != "ResourceNotFoundException":
                logger.debug("OAM sink policy read failed for %s: %s", s.get("Arn"), exc)
        return self._asset(
            arn=s["Arn"],
            name=s.get("Name") or s.get("Id", ""),
            asset_type=AssetType.LOG_SINK,
            metadata={
                "service": "oam",
                "kind": "oam_sink",
                "monitoring_account": True,
                "allowed_org_ids": orgs,
            },
            relations=relations,
            aliases=[s.get("Id")],
        )

    def _oam_link_asset(self, link: dict) -> CloudAsset:
        sink_arn = link.get("SinkArn")
        return self._asset(
            arn=link["Arn"],
            name=link.get("Label") or link.get("Id", ""),
            asset_type=AssetType.LOG_SINK,
            metadata={
                "service": "oam",
                "kind": "oam_link",
                "sink_arn": sink_arn,
                "monitoring_account_id": _arn_account(sink_arn),
                "resource_types": link.get("ResourceTypes", []),
            },
            relations=[
                rel(
                    sink_arn,
                    EdgeType.INVOKES,
                    "STREAMS_TO",
                    description="shares telemetry with monitoring account",
                    cross_account=self._cross_account(sink_arn) or None,
                )
            ],
        )

    async def _collect_oam(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("oam") as oam:
            sinks = [s async for s in self._paginate(oam, "list_sinks", "Items")]
            links = [link async for link in self._paginate(oam, "list_links", "Items")]
            sink_assets = await gather_limited(
                [lambda s=s: self._oam_sink_asset(oam, s) for s in sinks]
            )
            assets.extend(a for a in sink_assets if a)
        assets.extend(self._oam_link_asset(link) for link in links)
        return assets
