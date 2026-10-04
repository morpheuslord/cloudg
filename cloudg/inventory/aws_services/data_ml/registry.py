"""Public registries: ECR Public repositories (global, us-east-1 only)."""

from __future__ import annotations

from cloudg.inventory.aws_services.data_ml._common import DataMLHelpersMixin
from cloudg.schema.models import AssetType, CloudAsset


class RegistryCollectorsMixin(DataMLHelpersMixin):
    """ECR Public collector."""

    async def _collect_ecr_public(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ecr-public", region="us-east-1") as ecr:
            async for r in self._paginate(ecr, "describe_repositories", "repositories"):
                uri = r.get("repositoryUri")
                assets.append(
                    self._asset(
                        arn=r["repositoryArn"],
                        name=r.get("repositoryName", ""),
                        asset_type=AssetType.CONTAINER_REGISTRY,
                        region="global",
                        metadata={
                            "service": "ecr-public",
                            "public": True,
                            "registry_id": r.get("registryId"),
                            "repository_uri": uri,
                            "created_at": str(r.get("createdAt", "")),
                        },
                        exposed=True,
                        aliases=[uri],
                    )
                )
        return assets
