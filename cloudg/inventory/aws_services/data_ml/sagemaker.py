"""SageMaker: domains, notebook instances, endpoints (-> endpoint config ->
models) and models."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import identifier_refs, rel
from cloudg.inventory.aws_services.data_ml._common import (
    DataMLHelpersMixin,
    Relations,
    _bucket_arn,
    _gather_details,
    _kms_ref,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType


def _endpoint_output_rels(capture: dict, output: dict) -> Relations:
    """WRITES_TO relations for data capture and async inference output."""
    return [
        rel(
            _bucket_arn(capture.get("DestinationS3Uri")) if capture.get("EnableCapture") else None,
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="data capture",
        ),
        rel(
            _bucket_arn(output.get("S3OutputPath")),
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="async inference output",
        ),
        rel(
            _bucket_arn(output.get("S3FailurePath")),
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="async inference failures",
        ),
    ]


def _model_container_rels(c: dict) -> Relations:
    """Image, artifact, package and environment references of a container."""
    relations: Relations = []
    if c.get("Image"):
        relations.append(rel(c["Image"], EdgeType.USES_IMAGE, "RUNS_ON"))
    source = ((c.get("ModelDataSource") or {}).get("S3DataSource") or {}).get("S3Uri")
    for uri in (c.get("ModelDataUrl"), source):
        relations.append(
            rel(_bucket_arn(uri), EdgeType.REFERENCES, "READS_FROM", description="model artifacts")
        )
    relations.append(rel(c.get("ModelPackageName"), EdgeType.REFERENCES, "DEPENDS_ON"))
    relations += [
        rel(r, EdgeType.REFERENCES, "DEPENDS_ON", description="container environment")
        for r in identifier_refs(c.get("Environment"))
    ]
    return relations


class SageMakerCollectorsMixin(DataMLHelpersMixin):
    """SageMaker collectors."""

    async def _collect_sagemaker(self) -> list[CloudAsset]:
        async with self._client("sagemaker") as sm:
            return await self._gather_parts(
                "sagemaker",
                {
                    "domains": lambda: self._sagemaker_domains(sm),
                    "notebooks": lambda: self._sagemaker_notebooks(sm),
                    "endpoints": lambda: self._sagemaker_endpoints(sm),
                    "models": lambda: self._sagemaker_models(sm),
                },
            )

    async def _sagemaker_domains(self, sm: Any) -> list[CloudAsset]:
        domains = [d async for d in self._paginate(sm, "list_domains", "Domains")]
        return await _gather_details(domains, lambda x: self._sagemaker_domain(sm, x))

    async def _sagemaker_domain(self, sm: Any, summary: dict) -> CloudAsset:
        d = await sm.describe_domain(DomainId=summary["DomainId"])
        settings = d.get("DefaultUserSettings") or {}
        sgs = list(settings.get("SecurityGroups") or [])
        if d.get("SecurityGroupIdForDomainBoundary"):
            sgs.append(d["SecurityGroupIdForDomainBoundary"])
        sharing = settings.get("SharingSettings") or {}
        relations: Relations = self._subnet_rels(d.get("SubnetIds"))
        relations += [
            rel(
                settings.get("ExecutionRole"),
                EdgeType.ASSUMES_ROLE,
                "RUNS_ON",
                description="default execution role",
            ),
            rel(_kms_ref(d.get("KmsKeyId")), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(
                d.get("HomeEfsFileSystemId"),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="home directories",
            ),
            rel(
                _bucket_arn(sharing.get("S3OutputPath")),
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="notebook sharing output",
            ),
        ]
        public = d.get("AppNetworkAccessType") == "PublicInternetOnly"
        return self._asset(
            arn=d.get("DomainArn") or summary.get("DomainArn", ""),
            name=d.get("DomainName") or summary["DomainId"],
            asset_type=AssetType.ML_WORKSPACE,
            metadata={
                "service": "sagemaker",
                "kind": "domain",
                "domain_id": d.get("DomainId"),
                "status": d.get("Status"),
                "auth_mode": d.get("AuthMode"),
                "app_network_access": d.get("AppNetworkAccessType"),
                "vpc_id": d.get("VpcId"),
                "security_groups": sorted(set(sgs)),
                "kms_key_id": _kms_ref(d.get("KmsKeyId")),
                "url": d.get("Url"),
            },
            relations=relations,
            exposed=public,
            aliases=[d.get("DomainId")],
        )

    async def _sagemaker_notebooks(self, sm: Any) -> list[CloudAsset]:
        notebooks = [
            n async for n in self._paginate(sm, "list_notebook_instances", "NotebookInstances")
        ]
        return await _gather_details(notebooks, lambda x: self._sagemaker_notebook(sm, x))

    async def _sagemaker_notebook(self, sm: Any, summary: dict) -> CloudAsset:
        n = await sm.describe_notebook_instance(
            NotebookInstanceName=summary["NotebookInstanceName"]
        )
        kms = _kms_ref(n.get("KmsKeyId"))
        relations: Relations = self._subnet_rels(n.get("SubnetId"))
        relations += [
            rel(n.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
            rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(n.get("NetworkInterfaceId"), EdgeType.ATTACHED_TO, reverse=True),
        ]
        direct = n.get("DirectInternetAccess") == "Enabled"
        return self._asset(
            arn=n.get("NotebookInstanceArn") or summary.get("NotebookInstanceArn", ""),
            name=n.get("NotebookInstanceName") or summary["NotebookInstanceName"],
            asset_type=AssetType.ML_WORKSPACE,
            metadata={
                "service": "sagemaker",
                "kind": "notebook_instance",
                "status": n.get("NotebookInstanceStatus"),
                "instance_type": n.get("InstanceType"),
                "direct_internet_access": direct,
                "root_access": n.get("RootAccess"),
                "security_groups": n.get("SecurityGroups") or [],
                "kms_key_id": kms,
                "lifecycle_config": n.get("NotebookInstanceLifecycleConfigName"),
                "imds_min_version": (n.get("InstanceMetadataServiceConfiguration") or {}).get(
                    "MinimumInstanceMetadataServiceVersion"
                ),
                "url": n.get("Url"),
            },
            relations=relations,
            exposed=direct,
        )

    async def _sagemaker_endpoints(self, sm: Any) -> list[CloudAsset]:
        endpoints = [e async for e in self._paginate(sm, "list_endpoints", "Endpoints")]
        configs: dict[str, dict] = {}
        return await _gather_details(endpoints, lambda x: self._sagemaker_endpoint(sm, configs, x))

    @staticmethod
    async def _endpoint_config(sm: Any, configs: dict[str, dict], name: str) -> dict:
        """Endpoint config by name, cached across the endpoints sharing it."""
        if name not in configs:
            try:
                configs[name] = await sm.describe_endpoint_config(EndpointConfigName=name)
            except Exception as exc:
                logger.debug("Endpoint config %s lookup failed: %s", name, exc)
                configs[name] = {}
        return configs[name]

    def _endpoint_model_rels(self, variants: list[dict]) -> Relations:
        return [
            # SageMaker lower-cases resource names in ARNs; a bare name
            # could collide with the endpoint's own name.
            rel(
                self._arn("sagemaker", f"model/{v['ModelName'].lower()}")
                if v.get("ModelName")
                else None,
                EdgeType.REFERENCES,
                "DEPENDS_ON",
                description="serves model",
                variant=v.get("VariantName"),
            )
            for v in variants
        ]

    async def _sagemaker_endpoint(
        self, sm: Any, configs: dict[str, dict], summary: dict
    ) -> CloudAsset:
        e = await sm.describe_endpoint(EndpointName=summary["EndpointName"])
        cfg = (
            await self._endpoint_config(sm, configs, e.get("EndpointConfigName", ""))
            if e.get("EndpointConfigName")
            else {}
        )
        variants = (cfg.get("ProductionVariants") or []) + (
            cfg.get("ShadowProductionVariants") or []
        )
        relations = self._endpoint_model_rels(variants)
        kms = _kms_ref(cfg.get("KmsKeyId"))
        capture = cfg.get("DataCaptureConfig") or {}
        output = (cfg.get("AsyncInferenceConfig") or {}).get("OutputConfig") or {}
        relations += [
            rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(cfg.get("ExecutionRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
            *_endpoint_output_rels(capture, output),
        ]
        vpc = cfg.get("VpcConfig") or {}
        relations += self._subnet_rels(vpc.get("Subnets"))
        return self._asset(
            arn=e.get("EndpointArn") or summary.get("EndpointArn", ""),
            name=e.get("EndpointName") or summary["EndpointName"],
            asset_type=AssetType.ML_ENDPOINT,
            metadata={
                "service": "sagemaker",
                "status": e.get("EndpointStatus"),
                "endpoint_config": e.get("EndpointConfigName"),
                "models": [v.get("ModelName") for v in variants if v.get("ModelName")],
                "instance_types": sorted(
                    {v["InstanceType"] for v in variants if v.get("InstanceType")}
                ),
                "serverless": any(v.get("ServerlessConfig") for v in variants),
                "data_capture": bool(capture.get("EnableCapture")),
                "kms_key_id": kms,
                "security_groups": vpc.get("SecurityGroupIds") or [],
                "network_isolation": cfg.get("EnableNetworkIsolation"),
            },
            relations=relations,
        )

    async def _sagemaker_models(self, sm: Any) -> list[CloudAsset]:
        models = [m async for m in self._paginate(sm, "list_models", "Models")]
        return await _gather_details(models, lambda x: self._sagemaker_model(sm, x))

    async def _sagemaker_model(self, sm: Any, summary: dict) -> CloudAsset:
        m = await sm.describe_model(ModelName=summary["ModelName"])
        containers = ([m["PrimaryContainer"]] if m.get("PrimaryContainer") else []) + (
            m.get("Containers") or []
        )
        relations: Relations = [
            rel(m.get("ExecutionRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]
        images: list[str] = []
        for c in containers:
            if c.get("Image"):
                images.append(c["Image"])
            relations += _model_container_rels(c)
        vpc = m.get("VpcConfig") or {}
        relations += self._subnet_rels(vpc.get("Subnets"))
        arn = m.get("ModelArn") or summary.get("ModelArn", "")
        return self._asset(
            arn=arn,
            name=m.get("ModelName") or summary["ModelName"],
            asset_type=AssetType.ML_MODEL,
            metadata={
                "service": "sagemaker",
                "images": images,
                "network_isolation": m.get("EnableNetworkIsolation"),
                "security_groups": vpc.get("SecurityGroupIds") or [],
                "in_vpc": bool(vpc),
            },
            relations=relations,
            aliases=[arn.lower() if arn.lower() != arn else None],
        )
