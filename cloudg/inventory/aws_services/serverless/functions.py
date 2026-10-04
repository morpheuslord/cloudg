"""Lambda: execution role, VPC, layers, container image (-> ECR), DLQ, KMS
key, EFS access points, environment ARNs, event source mappings
(SQS/Kinesis/DynamoDB/MSK -> function), resource-policy invokers
(S3/SNS/EventBridge/API Gateway/logs -> function), function URLs."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory._util import image_repository
from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    error_code,
    gather_limited,
    identifier_refs,
    rel,
    resource_policy_relations,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split


def _function_relations(fn: dict, env: dict[str, Any]) -> list[dict | None]:
    """Role, KMS key, DLQ, layers, EFS mounts and environment references."""
    relations: list[dict | None] = [
        rel(fn.get("Role"), EdgeType.ASSUMES_ROLE, "RUNS_ON", description="execution role"),
        rel(fn.get("KMSKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
        rel(
            (fn.get("DeadLetterConfig") or {}).get("TargetArn"),
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="dead-letter target",
        ),
    ]
    relations += [
        rel(layer.get("Arn"), EdgeType.REFERENCES, "DEPENDS_ON", description="layer")
        for layer in fn.get("Layers", []) or []
    ]
    relations += [
        rel(fs.get("Arn"), EdgeType.REFERENCES, "READS_FROM", description="EFS mount")
        for fs in fn.get("FileSystemConfigs", []) or []
    ]
    relations += [
        rel(ref, EdgeType.REFERENCES, "DEPENDS_ON", description="environment reference")
        for ref in identifier_refs(env)
    ]
    return relations


def _event_source_relations(mappings: list[dict]) -> list[dict | None]:
    """Each event source mapping: the trigger and its failure destination."""
    relations: list[dict | None] = []
    for esm in mappings:
        relations.append(
            rel(
                esm.get("EventSourceArn"),
                EdgeType.INVOKES,
                "TRIGGERED_BY",
                reverse=True,
                description="event source mapping",
                state=esm.get("State"),
                batch_size=esm.get("BatchSize"),
            )
        )
        on_failure = ((esm.get("DestinationConfig") or {}).get("OnFailure") or {}).get(
            "Destination"
        )
        relations.append(
            rel(
                on_failure,
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="ESM failure destination",
            )
        )
    return relations


def _function_metadata(fn: dict, env: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    return {
        "runtime": fn.get("Runtime"),
        "handler": fn.get("Handler"),
        "package_type": fn.get("PackageType", "Zip"),
        "image_uri": extra["image_uri"],
        "architectures": fn.get("Architectures", []),
        "memory_size": fn.get("MemorySize"),
        "timeout": fn.get("Timeout"),
        "last_modified": fn.get("LastModified"),
        "vpc_config": fn.get("VpcConfig"),
        "role_arn": fn.get("Role"),
        "environment_keys": sorted(env),
        "layers": [layer.get("Arn") for layer in fn.get("Layers", []) or []],
        "event_sources": [m.get("EventSourceArn") for m in extra["mappings"]],
        "function_url_auth": extra["url_auth"],
        "policy_allows_public": extra["public_policy"],
        "tracing": (fn.get("TracingConfig") or {}).get("Mode"),
    }


class FunctionCollectorsMixin(AWSServiceMixin):
    # ------------------------------------------------------------------
    # Lambda (overrides the shallow base collector)
    # ------------------------------------------------------------------

    async def _collect_lambda(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("lambda") as lam:
            functions = [f async for f in self._paginate(lam, "list_functions", "Functions")]
            mappings = await self._lambda_event_source_mappings(lam)
            results = await gather_limited(
                [lambda f=f: self._lambda_function_asset(lam, f, mappings) for f in functions]
            )
            assets.extend(a for a in results if a)
        return assets

    async def _lambda_event_source_mappings(self, lam: Any) -> dict[str, list[dict]]:
        """Event source mappings keyed by function name."""
        mappings: dict[str, list[dict]] = {}
        try:
            async for esm in self._paginate(
                lam, "list_event_source_mappings", "EventSourceMappings"
            ):
                fn = (esm.get("FunctionArn") or "").split(":function:", 1)
                key = fn[1].split(":", 1)[0] if len(fn) == 2 else ""
                mappings.setdefault(key, []).append(esm)
        except Exception as exc:
            logger.debug("Event source mapping listing failed: %s", exc)
        return mappings

    async def _lambda_function_asset(
        self, lam: Any, fn: dict, mappings: dict[str, list[dict]]
    ) -> CloudAsset:
        name = fn.get("FunctionName", "")
        arn = fn.get("FunctionArn", "")
        env = (fn.get("Environment") or {}).get("Variables") or {}
        relations = _function_relations(fn, env)
        log_group = (fn.get("LoggingConfig") or {}).get("LogGroup") or f"/aws/lambda/{name}"
        relations.append(
            rel(self._arn("logs", f"log-group:{log_group}"), EdgeType.LOGS_TO, "LOGS_TO")
        )
        image_uri = await self._lambda_image_uri(lam, fn, relations)
        relations += _event_source_relations(mappings.get(name, []))
        url_auth = await self._lambda_url_auth(lam, name)
        public_policy = await self._lambda_policy(lam, name, relations)
        extra = {
            "image_uri": image_uri,
            "mappings": mappings.get(name, []),
            "url_auth": url_auth,
            "public_policy": public_policy,
        }
        return self._asset(
            arn=arn,
            name=name,
            asset_type=AssetType.LAMBDA_FUNCTION,
            metadata=_function_metadata(fn, env, extra),
            relations=relations,
            raw={k: v for k, v in fn.items() if k != "Environment"},
            exposed=url_auth == "NONE" or public_policy,
            aliases=[f"{arn}:$LATEST"],
        )

    async def _lambda_image_uri(
        self, lam: Any, fn: dict, relations: list[dict | None]
    ) -> str | None:
        """The container image of an Image-packaged function (-> its ECR repo)."""
        if fn.get("PackageType") != "Image":
            return None
        name = fn.get("FunctionName", "")
        image_uri = None
        try:
            full = await lam.get_function(FunctionName=name)
            image_uri = (full.get("Code") or {}).get("ImageUri")
            if image_uri:
                relations.append(
                    rel(
                        image_repository(image_uri),
                        EdgeType.USES_IMAGE,
                        "RUNS_ON",
                        description=f"runs {image_uri}",
                    )
                )
        except Exception as exc:
            logger.debug("get_function failed for %s: %s", name, exc)
        return image_uri

    async def _lambda_url_auth(self, lam: Any, name: str) -> str | None:
        try:
            url_cfg = await lam.get_function_url_config(FunctionName=name)
            return url_cfg.get("AuthType")
        except Exception as exc:
            if error_code(exc) != "ResourceNotFoundException":
                logger.debug("Function URL lookup failed for %s: %s", name, exc)
            return None

    async def _lambda_policy(self, lam: Any, name: str, relations: list[dict | None]) -> bool:
        """Add resource-policy invokers/grants; return whether it allows anyone."""
        try:
            pol = await lam.get_policy(FunctionName=name)
            pol_rels, public_policy = resource_policy_relations(pol.get("Policy"), self._account_id)
            relations.extend(pol_rels)
            return public_policy
        except Exception as exc:
            if error_code(exc) != "ResourceNotFoundException":
                logger.debug("Lambda policy read failed for %s: %s", name, exc)
            return False
