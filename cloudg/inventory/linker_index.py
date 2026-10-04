"""Identifier index and scope-aware resolution for the relationship linker.

Every collected asset is indexed under each identifier other services use
to reference it (ARN / resource ID, name, native short ID, URLs, DNS names,
image repositories, aliases). :meth:`IdentifierIndex.resolve` maps any such
reference back to an internal asset ID, scoping ambiguous names to the
referencing asset's account and region. Used by
:class:`~cloudg.inventory.linker.RelationshipLinker`.
"""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from cloudg.inventory._util import image_repository
from cloudg.schema.models import AssetType, CloudAsset, CloudProvider

_ARN_ACCOUNT_RE = re.compile(r"^arn:aws[a-zA-Z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")
_AZURE_SUB_RE = re.compile(r"^/subscriptions/([0-9a-fA-F-]{36})(?:/|$)")
_GCP_PROJECT_RE = re.compile(r"^//[a-z0-9.-]+\.googleapis\.com/projects/([a-z0-9-]+)(?:/|$)")
_ROLE_ARN_RE = re.compile(r"^arn:aws[a-zA-Z-]*:iam::(\d{12}):role/(.+)$")
_ASSUMED_ROLE_RE = re.compile(r"^arn:aws[a-zA-Z-]*:sts::(\d{12}):assumed-role/([^/]+)/")
_LAMBDA_QUALIFIED_RE = re.compile(r"^(arn:aws[a-zA-Z-]*:lambda:[^:]+:\d{12}:function:[^:]+):.+$")

# Identifiers that are globally unique; ambiguity never needs scoping
_GLOBAL_PREFIXES = (
    "arn:",
    "/subscriptions/",
    "/providers/",
    "//",
    "k8s://",
    "cloudg:",
    "aws-security:",
    "azure-security:",
    "entra:",
    "loganalytics:",
    "gcp-principal:",
    "k8s-gke://",
)
# Synthetic identifier schemes whose last path segment is not a usable short ID
_NO_TAIL_PREFIXES = ("k8s://", "k8s-gke://", "gcp-principal:", "entra:", "loganalytics:")

_ECR_HOST_RE = re.compile(r"\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(\.cn)?")


def _image_registry_host(ref: str) -> str:
    """Lower-cased registry host of an image reference or URL ('' if none).

    ``repo:tag`` alone has no registry; ``host/repo:tag`` and
    ``https://host/...`` do. Matching is done on the parsed host, never on a
    substring of the whole reference.
    """
    if "://" in ref:
        return (urlsplit(ref).hostname or "").lower()
    if "/" not in ref:
        return ""
    host = ref.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    return host.lower()


class IdentifierIndex:
    """Identifier -> asset ID index over a fixed inventory.

    Args:
        assets: The inventory to index.
    """

    def __init__(self, assets: list[CloudAsset]) -> None:
        self._assets = assets
        self._by_id: dict[str, CloudAsset] = {a.id: a for a in assets}
        self._index: dict[str, list[str]] = {}  # identifier -> asset ids
        self._build_index()

    def _register(self, identifier: Any, asset_id: str) -> None:
        if not isinstance(identifier, str) or not identifier:
            return
        ids = self._index.setdefault(identifier, [])
        if asset_id not in ids:
            ids.append(asset_id)
        lowered = identifier.lower()
        if lowered != identifier and (
            identifier.startswith(("/subscriptions/", "/providers/"))
            or "." in identifier
            and "/" not in identifier
        ):
            self._register(lowered, asset_id)

    def _index_asset(self, asset: CloudAsset) -> None:
        self._register(asset.arn, asset.id)
        self._register(asset.name, asset.id)

        # Native short IDs (last path/colon segment of the ARN / resource ID)
        if asset.arn and not asset.arn.startswith(_NO_TAIL_PREFIXES):
            tail = asset.arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
            if tail != asset.arn:
                self._register(tail, asset.id)

        md = asset.metadata
        for key in (
            "group_id",
            "route_table_id",
            "internet_gateway_id",
            "nat_gateway_id",
            "network_interface_id",
            "volume_id",
            "allocation_id",
            "network_acl_id",
            "peering_connection_id",
            "transit_gateway_id",
            "vpc_endpoint_id",
            "launch_template_id",
            "file_system_id",
            "queue_url",
            "repository_uri",
            "zone_id",
        ):
            self._register(md.get(key), asset.id)
        for alias in md.get("aliases", []) or []:
            self._register(alias, asset.id)

        if asset.asset_type in (AssetType.VPC, AssetType.VNET):
            self._register(md.get("vpc_id"), asset.id)
        if asset.asset_type == AssetType.SUBNET:
            self._register(md.get("subnet_id"), asset.id)
        if asset.asset_type in (AssetType.ELASTIC_IP, AssetType.EC2):
            self._register(md.get("public_ip"), asset.id)
        if asset.asset_type == AssetType.CLOUD_ACCOUNT and md.get("account_id"):
            self._register(md["account_id"], asset.id)

        # Names that other services reference by domain
        if asset.asset_type == AssetType.S3_BUCKET:
            self._register(f"{asset.name}.s3.amazonaws.com", asset.id)
        if asset.asset_type == AssetType.LOAD_BALANCER and md.get("dns_name"):
            self._register(md["dns_name"], asset.id)
            self._register(str(md["dns_name"]).lower().rstrip("."), asset.id)
        if asset.asset_type == AssetType.CLOUDFRONT and md.get("domain_name"):
            self._register(str(md["domain_name"]).lower(), asset.id)

    def _build_index(self) -> None:
        for asset in self._assets:
            self._index_asset(asset)

    def _pick(
        self, candidates: list[str], identifier: str, context: CloudAsset | None
    ) -> str | None:
        # Real assets win over placeholders (e.g. an Entra principal that is
        # a managed identity collected in another subscription).
        real = [c for c in candidates if not self._by_id[c].metadata.get("placeholder")]
        candidates = real or candidates
        if len(candidates) == 1:
            return candidates[0]
        if identifier.startswith(_GLOBAL_PREFIXES):
            return candidates[0]
        if context is None:
            return candidates[0]
        same_region = [
            c
            for c in candidates
            if self._by_id[c].account_id == context.account_id
            and self._by_id[c].region == context.region
        ]
        if same_region:
            return same_region[0]
        same_account = [c for c in candidates if self._by_id[c].account_id == context.account_id]
        if same_account:
            return same_account[0]
        global_scope = [c for c in candidates if self._by_id[c].region == "global"]
        if len(global_scope) == 1:
            return global_scope[0]
        return None  # ambiguous across accounts: do not guess

    def _lookup(self, identifier: str, context: CloudAsset | None) -> str | None:
        candidates = self._index.get(identifier)
        if candidates:
            return self._pick(candidates, identifier, context)
        return None

    def resolve(self, identifier: Any, context: CloudAsset | None = None) -> str | None:
        """Resolve any known identifier to an internal asset ID.

        Args:
            identifier: ARN, ID, name, URL, DNS name, image reference, ...
            context: The referencing asset, used to scope ambiguous names.
        """
        if not isinstance(identifier, str) or not identifier:
            return None
        found = self._lookup(identifier, context)
        if found:
            return found
        for candidate in self._variants(identifier):
            found = self._lookup(candidate, context)
            if found:
                return found
        # Role ARNs built from a bare name miss roles that have a path:
        # fall back to the role with that name in that account.
        m = _ROLE_ARN_RE.match(identifier)
        if m:
            found = self._role_in_account(m.group(2).rsplit("/", 1)[-1], m.group(1))
            if found:
                return found
        # Assumed-role sessions resolve to the role, scoped to its account
        m = _ASSUMED_ROLE_RE.match(identifier)
        if m:
            return self._role_in_account(m.group(2), m.group(1))
        return None

    def _role_in_account(self, role_name: str, account_id: str) -> str | None:
        """The IAM role with this name in this account, if collected."""
        for cid in self._index.get(role_name, []):
            a = self._by_id[cid]
            if a.asset_type == AssetType.IAM_ROLE and a.account_id == account_id:
                return cid
        return None

    def _variants(self, identifier: str) -> Iterable[str]:
        """Normalised forms of an identifier to retry when the exact one misses."""
        stripped = identifier.strip().rstrip(".").rstrip("/")
        if stripped != identifier:
            yield stripped
        lowered = stripped.lower()
        if lowered != stripped:
            yield lowered
        if lowered.startswith("dualstack."):
            yield lowered[len("dualstack.") :]
        if stripped.endswith(":*"):
            yield stripped[:-2]
        m = _LAMBDA_QUALIFIED_RE.match(stripped)
        if m:
            yield m.group(1)
        if stripped.startswith("arn:aws:s3:::") and "/" in stripped:
            yield stripped.split("/", 1)[0]
        registry = _image_registry_host(stripped)
        if _ECR_HOST_RE.fullmatch(registry) or (
            "/" in stripped and ":" in stripped.rsplit("/", 1)[-1]
        ):
            yield image_repository(stripped)
        if stripped.startswith("arn:aws:apigateway:") and "/stages/" in stripped:
            yield stripped.split("/stages/", 1)[0]
        if registry == "azurecr.io" or registry.endswith(".azurecr.io"):
            yield registry  # image -> registry login server

    @staticmethod
    def _foreign_account(identifier: str) -> tuple[CloudProvider, str, str] | None:
        """(provider, account id, account node identifier) an identifier lives in."""
        m = _ARN_ACCOUNT_RE.match(identifier) or re.match(
            r"^arn:aws[a-zA-Z-]*:iam::(\d{12}):", identifier
        )
        if m:
            return CloudProvider.AWS, m.group(1), f"arn:aws:iam::{m.group(1)}:root"
        if re.fullmatch(r"\d{12}", identifier):
            return CloudProvider.AWS, identifier, f"arn:aws:iam::{identifier}:root"
        m = _AZURE_SUB_RE.match(identifier)
        if m:
            sub = m.group(1).lower()
            return CloudProvider.AZURE, sub, f"/subscriptions/{sub}"
        m = _GCP_PROJECT_RE.match(identifier)
        if m:
            return (
                CloudProvider.GCP,
                m.group(1),
                f"//cloudresourcemanager.googleapis.com/projects/{m.group(1)}",
            )
        return None
