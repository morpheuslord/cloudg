"""Map nodes and edges of an AWS Organizations / Control Tower topology.

ORGANIZATION -> ORG_UNIT (tree) -> CLOUD_ACCOUNT, ORG_POLICY GOVERNS
targets, GUARDRAIL (control / baseline) GOVERNS targets, LANDING_ZONE
MANAGES the organization and its shared accounts. Account nodes use the
``arn:aws:iam::<id>:root`` identifier, so IAM trust and resource policies
from any collected account resolve onto them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudg.schema.models import AssetType, CloudAsset, CloudProvider, EdgeType

if TYPE_CHECKING:
    from cloudg.inventory.organization import OrgAccount, OrganizationTopology, OrgUnit


def account_ref(account_id: str) -> str:
    """Canonical identifier of an AWS account node."""
    return f"arn:aws:iam::{account_id}:root"


def _r(
    target: str,
    edge: EdgeType,
    relationship: str | None = None,
    reverse: bool = False,
    **props: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {"target": target, "edge": edge.value}
    if relationship:
        out["relationship"] = relationship
    if reverse:
        out["reverse"] = True
    if props:
        out["properties"] = props
    return out


class _AssetFactory:
    """Builds organization assets; owned by the management account by default."""

    def __init__(self, topology: OrganizationTopology) -> None:
        self.mgmt = topology.management_account_id
        self.org_arn = (
            topology.organization_arn or f"cloudg:aws:organization:{topology.organization_id}"
        )
        self.home = topology.control_tower_region or "global"

    def asset(
        self,
        arn: str,
        name: str,
        asset_type: AssetType,
        metadata: dict[str, Any],
        relations: list[dict[str, Any]],
        **fields: Any,
    ) -> CloudAsset:
        """One asset.

        Args:
            fields: Optional ``account_id`` (the management account),
                ``region`` (``"global"``) and ``aliases``.
        """
        md = dict(metadata)
        if relations:
            md["relations"] = relations
        aliases = fields.get("aliases")
        if aliases:
            md["aliases"] = [a for a in aliases if a]
        return CloudAsset(
            arn=arn,
            name=name,
            asset_type=asset_type,
            provider=CloudProvider.AWS,
            region=fields.get("region", "global"),
            account_id=fields.get("account_id", self.mgmt),
            metadata=md,
        )

    def unit(self, unit: OrgUnit, name: str, is_root: bool, parent: str) -> CloudAsset:
        """A root or OU node, contained by ``parent``."""
        return self.asset(
            unit.arn,
            name,
            AssetType.ORG_UNIT,
            {"ou_id": unit.id, "is_root": is_root, "path": ["Root"] if is_root else unit.path},
            [_r(parent, EdgeType.CONTAINS, reverse=True)],
            aliases=[unit.id],
        )

    def guardrail(
        self, item: dict[str, Any], ident: str, name: str, metadata: dict[str, Any]
    ) -> CloudAsset:
        """A Control Tower control or baseline governing its target."""
        return self.asset(
            item.get("arn") or f"{ident}@{item.get('targetIdentifier')}",
            name,
            AssetType.GUARDRAIL,
            metadata,
            [_r(item.get("targetIdentifier", ""), EdgeType.GOVERNS, "COMPLIANCE_GOVERNS")],
            region=self.home,
        )


def _organization_asset(topo: OrganizationTopology, f: _AssetFactory) -> CloudAsset:
    mgmt = f.mgmt
    return f.asset(
        f.org_arn,
        f"organization {topo.organization_id}",
        AssetType.ORGANIZATION,
        {
            "organization_id": topo.organization_id,
            "feature_set": topo.feature_set,
            "management_account_id": mgmt,
            "control_tower": topo.control_tower_enabled,
            "enabled_services": topo.enabled_services,
            "delegated_administrators": topo.delegated_administrators,
        },
        [_r(account_ref(mgmt), EdgeType.MANAGES, "OWNED_BY", reverse=True)] if mgmt else [],
        aliases=[topo.organization_id or ""],
    )


def _account_asset(
    topo: OrganizationTopology, f: _AssetFactory, acct: OrgAccount, shared_roles: dict[str, str]
) -> CloudAsset:
    return f.asset(
        account_ref(acct.id),
        acct.name,
        AssetType.CLOUD_ACCOUNT,
        {
            "account_id": acct.id,
            "status": acct.status,
            "ou_path": acct.ou_path,
            "email": acct.email,
            "joined_method": acct.joined_method,
            "joined": acct.joined,
            "management_account": acct.id == f.mgmt,
            "control_tower_role": shared_roles.get(acct.id),
            "delegated_admin_for": sorted(
                svc for svc, ids in topo.delegated_administrators.items() if acct.id in ids
            ),
        },
        [_r(acct.parent_id, EdgeType.CONTAINS, "ORG_CONTAINS_ACCOUNT", reverse=True)],
        account_id=acct.id,
        aliases=[acct.arn, acct.id],
    )


def _policy_assets(topo: OrganizationTopology, f: _AssetFactory) -> list[CloudAsset]:
    return [
        f.asset(
            pol.arn,
            pol.name,
            AssetType.ORG_POLICY,
            {
                "policy_id": pol.id,
                "policy_type": pol.type,
                "aws_managed": pol.aws_managed,
                "target_count": len(pol.targets),
            },
            [
                _r(
                    t,
                    EdgeType.GOVERNS,
                    "SCP_RESTRICTS"
                    if pol.type == "SERVICE_CONTROL_POLICY"
                    else "COMPLIANCE_GOVERNS",
                )
                for t in pol.targets
            ],
            aliases=[pol.id],
        )
        for pol in topo.policies
    ]


def _landing_zone_asset(topo: OrganizationTopology, f: _AssetFactory) -> CloudAsset:
    lz = topo.landing_zone or {}
    lz_rel = [_r(f.org_arn, EdgeType.MANAGES, "COMPLIANCE_GOVERNS")]
    for role, acct_id in topo.shared_accounts.items():
        lz_rel.append(_r(account_ref(acct_id), EdgeType.MANAGES, "OWNED_BY", role=role))
    return f.asset(
        lz.get("arn") or "cloudg:aws:controltower:landing-zone",
        "Control Tower landing zone",
        AssetType.LANDING_ZONE,
        {
            "version": lz.get("version"),
            "latest_available_version": lz.get("latestAvailableVersion"),
            "status": lz.get("status"),
            "drift_status": (lz.get("driftStatus") or {}).get("status"),
            "governed_regions": topo.governed_regions,
            "shared_accounts": topo.shared_accounts,
            "home_region": topo.control_tower_region,
        },
        lz_rel,
        region=f.home,
    )


def _guardrail_assets(topo: OrganizationTopology, f: _AssetFactory) -> list[CloudAsset]:
    assets: list[CloudAsset] = []
    for ctl in topo.enabled_controls:
        ident = ctl.get("controlIdentifier", "")
        metadata = {
            "kind": "control",
            "control_identifier": ident,
            "status": (ctl.get("statusSummary") or {}).get("status"),
            "drift_status": (ctl.get("driftStatusSummary") or {}).get("driftStatus"),
        }
        assets.append(f.guardrail(ctl, ident, ident.rsplit("/", 1)[-1], metadata))
    for bl in topo.enabled_baselines:
        ident = bl.get("baselineIdentifier", "")
        metadata = {
            "kind": "baseline",
            "baseline_identifier": ident,
            "baseline_version": bl.get("baselineVersion"),
            "status": (bl.get("statusSummary") or {}).get("status"),
        }
        assets.append(f.guardrail(bl, ident, f"baseline {ident.rsplit('/', 1)[-1]}", metadata))
    return assets


def topology_assets(topo: OrganizationTopology) -> list[CloudAsset]:
    """Organization structure as CloudAssets with declared relations."""
    f = _AssetFactory(topo)
    assets = [_organization_asset(topo, f)]
    assets += [f.unit(root, "Root", True, f.org_arn) for root in topo.roots]
    assets += [f.unit(ou, ou.name, False, ou.parent_id or "") for ou in topo.ous.values()]
    shared_roles = {acct: role for role, acct in topo.shared_accounts.items()}
    assets += [_account_asset(topo, f, acct, shared_roles) for acct in topo.accounts.values()]
    assets += _policy_assets(topo, f)
    if topo.landing_zone:
        assets.append(_landing_zone_asset(topo, f))
    assets += _guardrail_assets(topo, f)
    return assets
