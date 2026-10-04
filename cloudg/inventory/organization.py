"""AWS Organizations and Control Tower discovery.

Run from the management account (or an Organizations delegated
administrator) to:

1. Enumerate the organization: root, the full OU tree, every member
   account with its OU path and status, and all organization policies
   (SCPs, RCPs, tag, backup and AI opt-out policies) with their targets.
2. Detect Control Tower: the landing zone (version, drift, governed
   regions, log archive / audit / config / backup accounts), every enabled
   control and baseline and the OU or account it applies to.
3. Pick the accounts to fan collection out to (OU filters, exclusions,
   suspended accounts) and, with Control Tower, the governed regions.

The topology is also turned into map nodes and edges
(:mod:`cloudg.inventory.organization_assets`).

All calls are read-only (``Describe*`` / ``List*`` / ``Get*``).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

# account_ref is re-exported: it is part of this module's public API.
from cloudg.inventory.organization_assets import account_ref, topology_assets
from cloudg.schema.models import CloudAsset

logger = logging.getLogger(__name__)

DEFAULT_MEMBER_ROLE = "AWSControlTowerExecution"

_POLICY_TYPES = [
    "SERVICE_CONTROL_POLICY",
    "RESOURCE_CONTROL_POLICY",
    "TAG_POLICY",
    "BACKUP_POLICY",
    "AISERVICES_OPT_OUT_POLICY",
]
_CT_HOME_REGION_CANDIDATES = [
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "eu-west-2",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-southeast-1",
    "ca-central-1",
    "ap-south-1",
    "eu-north-1",
    "sa-east-1",
]


@dataclass
class OrgAccount:
    id: str
    name: str
    arn: str
    status: str
    parent_id: str
    ou_path: list[str] = field(default_factory=list)
    email: str | None = None
    joined_method: str | None = None
    joined: str | None = None


@dataclass
class OrgUnit:
    id: str
    name: str
    arn: str
    parent_id: str | None
    path: list[str] = field(default_factory=list)
    is_root: bool = False


@dataclass
class OrgPolicy:
    id: str
    name: str
    arn: str
    type: str
    aws_managed: bool
    targets: list[str] = field(default_factory=list)


@dataclass
class OrganizationTopology:
    """Everything discovered about the organization and its landing zone."""

    organization_id: str | None = None
    organization_arn: str | None = None
    management_account_id: str | None = None
    caller_account_id: str | None = None
    feature_set: str | None = None
    roots: list[OrgUnit] = field(default_factory=list)
    ous: dict[str, OrgUnit] = field(default_factory=dict)
    accounts: dict[str, OrgAccount] = field(default_factory=dict)
    policies: list[OrgPolicy] = field(default_factory=list)
    delegated_administrators: dict[str, list[str]] = field(default_factory=dict)
    enabled_services: list[str] = field(default_factory=list)
    landing_zone: dict[str, Any] | None = None
    governed_regions: list[str] = field(default_factory=list)
    shared_accounts: dict[str, str] = field(default_factory=dict)  # role -> account id
    enabled_controls: list[dict[str, Any]] = field(default_factory=list)
    enabled_baselines: list[dict[str, Any]] = field(default_factory=list)
    control_tower_region: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def control_tower_enabled(self) -> bool:
        return self.landing_zone is not None

    # ------------------------------------------------------------------
    # Account selection
    # ------------------------------------------------------------------

    def _resolve_ou(self, ref: str) -> str | None:
        ref_l = ref.lower()
        for unit in list(self.ous.values()) + self.roots:
            if ref in (unit.id, unit.arn) or unit.name.lower() == ref_l:
                return unit.id
        return None

    def _descendant_ous(self, ou_id: str) -> set[str]:
        out = {ou_id}
        changed = True
        while changed:
            changed = False
            for unit in self.ous.values():
                if unit.parent_id in out and unit.id not in out:
                    out.add(unit.id)
                    changed = True
        return out

    def target_accounts(
        self,
        include_ous: list[str] | None = None,
        exclude_accounts: list[str] | None = None,
        include_management_account: bool = True,
        include_suspended: bool = False,
    ) -> list[str]:
        """Account IDs to collect, after OU / exclusion / status filters."""
        allowed_ous: set[str] | None = None
        if include_ous:
            allowed_ous = set()
            for ref in include_ous:
                ou_id = self._resolve_ou(ref)
                if ou_id is None:
                    logger.warning("OU filter %r matched no OU in the organization", ref)
                    continue
                allowed_ous |= self._descendant_ous(ou_id)
        excluded = set(exclude_accounts or [])
        selected = []
        for acct in self.accounts.values():
            if acct.id in excluded:
                continue
            if acct.status != "ACTIVE" and not include_suspended:
                continue
            if acct.id == self.management_account_id and not include_management_account:
                continue
            if allowed_ous is not None and acct.parent_id not in allowed_ous:
                continue
            selected.append(acct.id)
        return sorted(selected)

    # ------------------------------------------------------------------
    # Map nodes and edges
    # ------------------------------------------------------------------

    def to_assets(self) -> list[CloudAsset]:
        """Organization structure as CloudAssets with declared relations."""
        return topology_assets(self)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["control_tower_enabled"] = self.control_tower_enabled
        return data


# ----------------------------------------------------------------------
# Discovery
# ----------------------------------------------------------------------


def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> list[Any]:
    items: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        items.extend(page.get(key, []) or [])
    return items


def _parse_manifest(manifest: Any) -> tuple[list[str], dict[str, str]]:
    """Governed regions and shared accounts from a landing zone manifest.

    Handles both the 3.x (``organizationStructure``, ``centralizedLogging``,
    ``securityRoles``) and 4.x (``config``, ``backup``) layouts.
    """
    if not isinstance(manifest, dict):
        return [], {}
    regions = [str(r) for r in manifest.get("governedRegions", []) or []]
    shared: dict[str, str] = {}

    def take(role: str, block: Any) -> None:
        if isinstance(block, dict) and block.get("accountId"):
            shared[role] = str(block["accountId"])

    take("log_archive", manifest.get("centralizedLogging"))
    take("audit", manifest.get("securityRoles"))
    take("config_aggregator", manifest.get("config"))
    backup_cfg = (manifest.get("backup") or {}).get("configurations") or {}
    take("backup_admin", backup_cfg.get("backupAdmin"))
    take("central_backup", backup_cfg.get("centralBackup"))
    return regions, shared


def _ct_regions(session: Any, home_region: str | None) -> list[str]:
    """Regions to probe for the landing zone: the hint, the session's, then the usual homes."""
    regions = [home_region] if home_region else []
    session_region = getattr(session, "region_name", None)
    if session_region and session_region not in regions:
        regions.append(session_region)
    regions += [r for r in _CT_HOME_REGION_CANDIDATES if r not in regions]
    return regions


def _load_landing_zone(ct: Any, topology: OrganizationTopology, lz_arn: Any, region: str) -> None:
    try:
        lz = ct.get_landing_zone(landingZoneIdentifier=lz_arn).get("landingZone", {})
    except Exception as exc:
        topology.errors.append(f"controltower:get_landing_zone: {exc}")
        lz = {"arn": lz_arn}
    topology.landing_zone = {k: v for k, v in lz.items() if k != "manifest"}
    topology.landing_zone.setdefault("arn", lz_arn)
    topology.control_tower_region = region
    topology.governed_regions, topology.shared_accounts = _parse_manifest(lz.get("manifest"))


def _load_controls(ct: Any, topology: OrganizationTopology) -> None:
    """Enabled controls and baselines of the landing zone."""
    try:
        topology.enabled_controls = _paginate(ct, "list_enabled_controls", "enabledControls")
    except Exception:
        # Older API revisions require a target: query each OU instead.
        controls: list[dict[str, Any]] = []
        for unit in list(topology.ous.values()):
            try:
                controls += _paginate(
                    ct, "list_enabled_controls", "enabledControls", targetIdentifier=unit.arn
                )
            except Exception as exc:
                logger.debug("Enabled controls for %s unavailable: %s", unit.id, exc)
        topology.enabled_controls = controls
    try:
        topology.enabled_baselines = _paginate(ct, "list_enabled_baselines", "enabledBaselines")
    except Exception as exc:
        logger.debug("Enabled baselines unavailable: %s", exc)


def discover_control_tower(
    session: Any,
    topology: OrganizationTopology,
    home_region: str | None = None,
) -> None:
    """Fill landing zone, governed regions, controls and baselines in place."""
    for region in _ct_regions(session, home_region):
        try:
            ct = session.client("controltower", region_name=region)
            zones = _paginate(ct, "list_landing_zones", "landingZones")
        except Exception as exc:
            logger.debug("Control Tower lookup in %s failed: %s", region, exc)
            if home_region:
                topology.errors.append(f"controltower:{region}: {exc}")
            continue
        if not zones:
            continue
        _load_landing_zone(ct, topology, zones[0].get("arn"), region)
        _load_controls(ct, topology)
        logger.info(
            "Control Tower landing zone %s in %s: %d governed regions, %d controls",
            topology.landing_zone.get("version"),
            region,
            len(topology.governed_regions),
            len(topology.enabled_controls),
        )
        return
    logger.info("No Control Tower landing zone found")


_DELEGATED_ADMIN_SERVICES = (
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "inspector2.amazonaws.com",
    "config.amazonaws.com",
    "access-analyzer.amazonaws.com",
    "macie.amazonaws.com",
    "detective.amazonaws.com",
    "fms.amazonaws.com",
    "sso.amazonaws.com",
)


def _describe_organization(session: Any, topology: OrganizationTopology) -> Any:
    """Caller identity and organization details; returns the Organizations client."""
    try:
        topology.caller_account_id = session.client("sts").get_caller_identity().get("Account")
    except Exception as exc:
        logger.debug("Caller identity lookup failed: %s", exc)

    org = session.client("organizations")
    try:
        info = org.describe_organization()["Organization"]
    except Exception as exc:
        raise RuntimeError(f"Organizations discovery failed: {exc}") from exc
    topology.organization_id = info.get("Id")
    topology.organization_arn = info.get("Arn")
    topology.management_account_id = info.get("MasterAccountId")
    topology.feature_set = info.get("FeatureSet")
    return org


def _walk(org: Any, topology: OrganizationTopology, parent_id: str, path: list[str]) -> None:
    """Accounts and OUs below ``parent_id``, recursively."""
    for acct in _paginate(org, "list_accounts_for_parent", "Accounts", ParentId=parent_id):
        topology.accounts[acct["Id"]] = OrgAccount(
            id=acct["Id"],
            name=acct.get("Name", acct["Id"]),
            arn=acct.get("Arn", ""),
            status=acct.get("State") or acct.get("Status", "ACTIVE"),
            parent_id=parent_id,
            ou_path=list(path),
            email=acct.get("Email"),
            joined_method=acct.get("JoinedMethod"),
            joined=str(acct.get("JoinedTimestamp", "")) or None,
        )
    for ou in _paginate(
        org, "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=parent_id
    ):
        unit = OrgUnit(
            id=ou["Id"],
            name=ou.get("Name", ou["Id"]),
            arn=ou.get("Arn", ""),
            parent_id=parent_id,
            path=path + [ou.get("Name", ou["Id"])],
        )
        topology.ous[unit.id] = unit
        _walk(org, topology, unit.id, unit.path)


def _root_policies(org: Any, topology: OrganizationTopology, root: dict[str, Any]) -> None:
    """Policies of every policy type enabled on ``root``, with their targets."""
    enabled = {p.get("Type") for p in root.get("PolicyTypes", []) if p.get("Status") == "ENABLED"}
    policy_types = [t for t in _POLICY_TYPES if t in enabled or not root.get("PolicyTypes")]
    for ptype in policy_types:
        try:
            for pol in _paginate(org, "list_policies", "Policies", Filter=ptype):
                targets = [
                    t["TargetId"]
                    for t in _paginate(
                        org, "list_targets_for_policy", "Targets", PolicyId=pol["Id"]
                    )
                ]
                topology.policies.append(
                    OrgPolicy(
                        id=pol["Id"],
                        name=pol.get("Name", pol["Id"]),
                        arn=pol.get("Arn", ""),
                        type=ptype,
                        aws_managed=pol.get("AwsManaged", False),
                        targets=targets,
                    )
                )
        except Exception as exc:
            logger.debug("Policy type %s unavailable: %s", ptype, exc)


def _service_access(org: Any, topology: OrganizationTopology) -> None:
    """Trusted service access and delegated administrators."""
    try:
        for svc in _paginate(
            org, "list_aws_service_access_for_organization", "EnabledServicePrincipals"
        ):
            topology.enabled_services.append(svc.get("ServicePrincipal", ""))
    except Exception as exc:
        logger.debug("Trusted service access listing failed: %s", exc)
    for svc in _DELEGATED_ADMIN_SERVICES:
        try:
            admins = _paginate(
                org,
                "list_delegated_administrators",
                "DelegatedAdministrators",
                ServicePrincipal=svc,
            )
            if admins:
                topology.delegated_administrators[svc.split(".", 1)[0]] = [a["Id"] for a in admins]
        except Exception as exc:
            logger.debug("Delegated admin lookup for %s failed: %s", svc, exc)
            break  # usually AccessDenied for everything when not management


def discover_organization(
    session: Any,
    control_tower: bool = True,
    home_region: str | None = None,
) -> OrganizationTopology:
    """Discover the organization reachable from ``session`` (blocking).

    Raises:
        RuntimeError: If the caller cannot describe the organization (not
            in an organization, or not the management / delegated admin).
    """
    topology = OrganizationTopology()
    org = _describe_organization(session, topology)
    try:
        roots = _paginate(org, "list_roots", "Roots")
    except Exception as exc:
        raise RuntimeError(
            f"Listing the organization needs the management account or a delegated administrator: {exc}"
        ) from exc

    for root in roots:
        unit = OrgUnit(
            id=root["Id"],
            name=root.get("Name", "Root"),
            arn=root.get("Arn", ""),
            parent_id=None,
            path=["Root"],
            is_root=True,
        )
        topology.roots.append(unit)
        _walk(org, topology, unit.id, ["Root"])
        _root_policies(org, topology, root)

    _service_access(org, topology)
    if control_tower:
        discover_control_tower(session, topology, home_region)

    logger.info(
        "Organization %s: %d accounts in %d OUs, %d policies",
        topology.organization_id,
        len(topology.accounts),
        len(topology.ous),
        len(topology.policies),
    )
    return topology


# Public API, including names re-exported from the split-out modules
__all__ = [
    "account_ref",
    "DEFAULT_MEMBER_ROLE",
    "discover_control_tower",
    "discover_organization",
    "OrgAccount",
    "OrganizationTopology",
    "OrgPolicy",
    "OrgUnit",
    "topology_assets",
]
