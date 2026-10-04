"""ARM resource type -> AssetType classification."""

from __future__ import annotations

from cloudg.inventory.catalogs import asset_type_map, load_catalog
from cloudg.schema.models import AssetType

# Maps lowercase ARM resource types to normalised AssetTypes.
# ARM type -> AssetType; the table lives in catalogs/azure_arm_types.yaml.
_ARM_TYPE_MAP: dict[str, AssetType] = asset_type_map(
    load_catalog("azure_arm_types").get("arm_types"), "azure_arm_types"
)


def asset_type_from_arm(resource_type: str | None, kind: str | None = None) -> AssetType:
    """Best-effort AssetType classification from an ARM resource type.

    Args:
        resource_type: ARM type, e.g. ``Microsoft.Web/sites`` (any case).
        kind: The resource ``kind``; distinguishes function apps from web apps.
    """
    if not resource_type:
        return AssetType.OTHER
    rtype = resource_type.lower()
    if (
        rtype in ("microsoft.web/sites", "microsoft.web/sites/slots")
        and kind
        and "functionapp" in kind.lower()
    ):
        return AssetType.CLOUD_FUNCTION
    return _ARM_TYPE_MAP.get(rtype, AssetType.OTHER)
