"""ECR repositories with image inventory, scan findings summary, scan
configuration, encryption and cross-account pull grants."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, error_code, gather_limited, rel
from cloudg.inventory.aws_services._policy_grants import principal_grants
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split


def _image_severities(images: list[dict]) -> dict[str, int]:
    """Scan finding counts per severity, summed over the sampled images."""
    severities: dict[str, int] = {}
    for img in images:
        counts = (img.get("imageScanFindingsSummary") or {}).get("findingSeverityCounts", {})
        for sev, n in counts.items():
            severities[sev] = severities.get(sev, 0) + int(n)
    return severities


def _image_summary(i: dict) -> dict[str, Any]:
    return {
        "digest": i.get("imageDigest"),
        "tags": i.get("imageTags", []),
        "pushed_at": str(i.get("imagePushedAt", "")),
        "scan_status": (i.get("imageScanStatus") or {}).get("status"),
        "size_bytes": i.get("imageSizeInBytes"),
    }


def _repository_metadata(
    repo: dict, registry: dict[str, Any], images: list[dict], public: bool
) -> dict[str, Any]:
    enc = repo.get("encryptionConfiguration") or {}
    return {
        "registry": "ecr",
        "repository_uri": repo.get("repositoryUri"),
        "image_tag_mutability": repo.get("imageTagMutability"),
        "scan_on_push": (repo.get("imageScanningConfiguration") or {}).get("scanOnPush"),
        "registry_scan_type": registry.get("scan_type"),
        "replication_destinations": registry.get("replication_destinations", []),
        "encryption_type": enc.get("encryptionType"),
        "kms_key_id": enc.get("kmsKey"),
        "image_count_sampled": len(images),
        "latest_images": [_image_summary(i) for i in images[:5]],
        "image_findings": _image_severities(images),
        "policy_allows_public": public,
    }


class EcrCollectorsMixin(AWSServiceMixin):
    _max_images: int = 20

    async def _collect_ecr(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("ecr") as ecr:
            registry = await self._ecr_registry_settings(ecr)
            repos = [r async for r in self._paginate(ecr, "describe_repositories", "repositories")]
            results = await gather_limited(
                [lambda r=r: self._ecr_repository_asset(ecr, r, registry) for r in repos]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _ecr_registry_settings(self, ecr: Any) -> dict[str, Any]:
        """Registry-wide scan type and replication destinations."""
        registry: dict[str, Any] = {}
        try:
            scan_cfg = await ecr.get_registry_scanning_configuration()
            registry["scan_type"] = (scan_cfg.get("scanningConfiguration") or {}).get("scanType")
        except Exception as exc:
            logger.debug("ECR registry scanning config unavailable: %s", exc)
        try:
            reg = await ecr.describe_registry()
            rules = (reg.get("replicationConfiguration") or {}).get("rules", [])
            registry["replication_destinations"] = [
                d for r in rules for d in r.get("destinations", [])
            ]
        except Exception as exc:
            logger.debug("ECR describe_registry unavailable: %s", exc)
        return registry

    async def _ecr_images(self, ecr: Any, name: str) -> list[dict]:
        """A sample of the repository's images, newest first."""
        images: list[dict] = []
        if self._max_images:
            try:
                paginator = ecr.get_paginator("describe_images")
                async for page in paginator.paginate(
                    repositoryName=name,
                    PaginationConfig={"MaxItems": self._max_images},
                ):
                    images.extend(page.get("imageDetails", []))
            except Exception as exc:
                logger.debug("describe_images failed for %s: %s", name, exc)
        images.sort(key=lambda i: str(i.get("imagePushedAt", "")), reverse=True)
        return images

    @staticmethod
    async def _ecr_policy_grants(ecr: Any, name: str) -> tuple[list[dict | None], bool]:
        """Principals the repository policy lets pull, plus whether anyone can."""
        try:
            pol = await ecr.get_repository_policy(repositoryName=name)
            return principal_grants(
                pol.get("policyText"), "repository policy grant", conditioned_public=True
            )
        except Exception as exc:
            if error_code(exc) != "RepositoryPolicyNotFoundException":
                logger.debug("ECR policy read failed for %s: %s", name, exc)
            return [], False

    async def _ecr_repository_asset(
        self, ecr: Any, repo: dict, registry: dict[str, Any]
    ) -> CloudAsset:
        name = repo["repositoryName"]
        images = await self._ecr_images(ecr, name)
        relations, policy_public = await self._ecr_policy_grants(ecr, name)
        enc = repo.get("encryptionConfiguration") or {}
        relations.append(rel(enc.get("kmsKey"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"))
        return self._asset(
            arn=repo["repositoryArn"],
            name=name,
            asset_type=AssetType.CONTAINER_REGISTRY,
            metadata=_repository_metadata(repo, registry, images, policy_public),
            relations=relations,
            raw=repo,
            exposed=policy_public,
            aliases=[repo.get("repositoryUri")],
        )
