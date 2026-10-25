"""ML and generative AI: Vertex AI Agent Engine (reasoning engines), Vector
Search, Agent Builder (Discovery Engine, Dialogflow CX), Model Armor,
pipelines and training jobs, Feature Store and Colab Enterprise runtimes."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.gcp_relations._refs import bq_ref, gcs_ref, parent_of
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, dig, full_name, image_repository
from cloudg.schema.models import EdgeType

_AI = "aiplatform"


def _data_ref(uri: Any) -> str | None:
    """A ``gs://`` or ``bq://`` data location."""
    if not isinstance(uri, str) or not uri:
        return None
    if uri.startswith("bq://"):
        return bq_ref(uri)
    if uri.startswith("gs://"):
        return gcs_ref(uri.split("*", 1)[0])
    return None


# ---------------------------------------------------------------------------
# Agents and retrieval
# ---------------------------------------------------------------------------


@_extractor("aiplatform.googleapis.com/ReasoningEngine")
def _reasoning_engine(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    spec = d.get("spec") or {}
    pkg = spec.get("packageSpec") or {}
    for key in ("pickleObjectGcsUri", "dependencyFilesGcsUri", "requirementsGcsUri"):
        out.add(_data_ref(pkg.get(key)), EdgeType.REFERENCES, "READS_FROM", description=key)
    deploy = spec.get("deploymentSpec") or {}
    for env in _list(deploy.get("secretEnv")):
        secret = dig(env, "secretRef", "secret") if isinstance(env, dict) else None
        if secret and ctx.project_id and "/" not in secret:
            secret = f"projects/{ctx.project_id}/secrets/{secret}"
        out.add(full_name(secret, "secretmanager"), EdgeType.REFERENCES, "READS_FROM")
    out.add(
        full_name(dig(deploy, "pscInterfaceConfig", "networkAttachment"), "compute"),
        EdgeType.ATTACHED_TO,
        description="PSC interface network attachment",
    )
    out.sa(spec.get("serviceAccount") or d.get("serviceAccount"), ctx, "agent identity")
    out.metadata.update(
        agent_framework=spec.get("agentFramework"),
        python_version=pkg.get("pythonVersion"),
        class_methods=len(_list(spec.get("classMethods"))),
    )


@_extractor("aiplatform.googleapis.com/Index")
def _vector_index(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        _data_ref(dig(d, "metadata", "contentsDeltaUri")),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="index contents",
    )
    out.metadata.update(
        update_method=d.get("indexUpdateMethod"),
        dimensions=dig(d, "metadata", "config", "dimensions"),
        deployed_count=len(_list(d.get("deployedIndexes"))),
    )


@_extractor("aiplatform.googleapis.com/IndexEndpoint")
def _vector_index_endpoint(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    for dep in _list(d.get("deployedIndexes")):
        if isinstance(dep, dict):
            out.add(
                full_name(dep.get("index"), _AI),
                EdgeType.ROUTE,
                "SERVES_TRAFFIC_TO",
                deployed_index=dep.get("id"),
            )
    out.add(full_name(d.get("network"), "compute"), EdgeType.ATTACHED_TO)
    psc = d.get("privateServiceConnectConfig") or {}
    for project in _list(psc.get("projectAllowlist")):
        out.add(
            f"//cloudresourcemanager.googleapis.com/projects/{project}",
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            reverse=True,
            description="PSC project allowlist",
        )
    if d.get("publicEndpointEnabled"):
        out.expose("Vector Search public endpoint", protocol="tcp", ports=["443"])
        out.alias(
            f"https://{d['publicEndpointDomainName']}"
            if d.get("publicEndpointDomainName")
            else None
        )
    out.metadata.update(
        public_endpoint=bool(d.get("publicEndpointEnabled")),
        private_service_connect=bool(psc.get("enablePrivateServiceConnect")),
    )


@_extractor("discoveryengine.googleapis.com/DataStore")
def _de_data_store(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(parent_of(ctx.name, "dataStores"), EdgeType.CONTAINS, reverse=True)
    out.metadata.update(
        industry_vertical=d.get("industryVertical"),
        content_config=d.get("contentConfig"),
        solution_types=list(d.get("solutionTypes") or []),
    )


@_extractor("discoveryengine.googleapis.com/Engine")
def _de_engine(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    collection = parent_of(ctx.name, "engines")
    for ds in _list(d.get("dataStoreIds")):
        if collection and isinstance(ds, str):
            out.add(
                f"{collection}/dataStores/{ds}",
                EdgeType.REFERENCES,
                "READS_FROM",
                description="engine data store",
            )
    out.add(
        full_name(dig(d, "chatEngineMetadata", "dialogflowAgent"), "dialogflow"),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
    )
    out.metadata.update(
        solution_type=d.get("solutionType"), industry_vertical=d.get("industryVertical")
    )


@_extractor("discoveryengine.googleapis.com/Assistant", "discoveryengine.googleapis.com/Collection")
def _de_child(ctx: GCPContext, out: Extracted) -> None:
    out.add(parent_of(ctx.name, "assistants"), EdgeType.CONTAINS, reverse=True)


@_extractor("dialogflow.googleapis.com/Agent")
def _dialogflow_agent(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("securitySettings"), "dialogflow"), EdgeType.REFERENCES, "DEPENDS_ON")
    logging_cfg = dig(d, "advancedSettings", "loggingSettings", default={}) or {}
    out.metadata.update(
        default_language=d.get("defaultLanguageCode"),
        stackdriver_logging=logging_cfg.get("enableStackdriverLogging"),
        interaction_logging=logging_cfg.get("enableInteractionLogging"),
        locked=d.get("locked"),
    )


@_extractor("dialogflow.googleapis.com/KnowledgeBase")
def _dialogflow_kb(ctx: GCPContext, out: Extracted) -> None:
    out.metadata["language"] = ctx.data.get("languageCode")


@_extractor("modelarmor.googleapis.com/Template")
def _model_armor(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    cfg = d.get("filterConfig") or {}
    out.metadata.update(
        filters=sorted(cfg.keys()),
        log_operations=dig(d, "templateMetadata", "logTemplateOperations"),
        log_sanitize_operations=dig(d, "templateMetadata", "logSanitizeOperations"),
    )


# ---------------------------------------------------------------------------
# Pipelines, training and prediction jobs
# ---------------------------------------------------------------------------


def _job_spec(ctx: GCPContext, out: Extracted, spec: Any) -> list[str]:
    """Identity, network, images and output of a CustomJob-shaped spec."""
    if not isinstance(spec, dict):
        return []
    out.sa(spec.get("serviceAccount"), ctx, "training job identity")
    out.add(full_name(spec.get("network"), "compute"), EdgeType.ATTACHED_TO)
    images = []
    for pool in _list(spec.get("workerPoolSpecs")):
        if not isinstance(pool, dict):
            continue
        image = dig(pool, "containerSpec", "imageUri") or dig(
            pool, "pythonPackageSpec", "executorImageUri"
        )
        if image:
            images.append(image)
            out.add(image_repository(image), EdgeType.USES_IMAGE, "RUNS_ON")
        for uri in _list(dig(pool, "pythonPackageSpec", "packageUris")):
            out.add(_data_ref(uri), EdgeType.REFERENCES, "READS_FROM")
    out.add(
        _data_ref(dig(spec, "baseOutputDirectory", "outputUriPrefix")),
        EdgeType.REFERENCES,
        "WRITES_TO",
        description="job output",
    )
    out.add(full_name(spec.get("tensorboard"), _AI), EdgeType.LOGS_TO, "LOGS_TO")
    return images


@_extractor("aiplatform.googleapis.com/CustomJob")
def _custom_job(ctx: GCPContext, out: Extracted) -> None:
    images = _job_spec(ctx, out, ctx.data.get("jobSpec"))
    out.metadata.update(images=images, job_state=ctx.data.get("state"))


@_extractor("aiplatform.googleapis.com/HyperparameterTuningJob", "aiplatform.googleapis.com/NasJob")
def _tuning_job(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    spec = d.get("trialJobSpec") or dig(
        d, "nasJobSpec", "multiTrialAlgorithmSpec", "searchTrialSpec", "searchTrialJobSpec"
    )
    out.metadata.update(images=_job_spec(ctx, out, spec), job_state=d.get("state"))


@_extractor("aiplatform.googleapis.com/TrainingPipeline")
def _training_pipeline(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    loc = parent_of(ctx.name, "trainingPipelines")
    dataset = dig(d, "inputDataConfig", "datasetId")
    if loc and dataset:
        out.add(
            f"{loc}/datasets/{dataset}",
            EdgeType.REFERENCES,
            "READS_FROM",
            description="training data",
        )
    model = dig(d, "modelToUpload", "name") or d.get("modelId")
    if loc and model:
        out.add(
            model if "/" in str(model) else f"{loc}/models/{model}",
            EdgeType.REFERENCES,
            "WRITES_TO",
            description="trained model",
        )
    out.metadata.update(
        training_task=str(d.get("trainingTaskDefinition") or "").rsplit("/", 1)[-1] or None,
        pipeline_state=d.get("state"),
    )


@_extractor("aiplatform.googleapis.com/PipelineJob")
def _pipeline_job(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.sa(d.get("serviceAccount") or "default", ctx, "pipeline identity")
    out.add(full_name(d.get("network"), "compute"), EdgeType.ATTACHED_TO)
    out.add(
        _data_ref(dig(d, "runtimeConfig", "gcsOutputDirectory")),
        EdgeType.REFERENCES,
        "WRITES_TO",
        description="pipeline root",
    )
    out.add(_data_ref(d.get("templateUri")), EdgeType.REFERENCES, "READS_FROM")
    out.metadata.update(template_uri=d.get("templateUri"), pipeline_state=d.get("state"))


@_extractor("aiplatform.googleapis.com/BatchPredictionJob")
def _batch_prediction(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("model"), _AI), EdgeType.REFERENCES, "DEPENDS_ON")
    src = d.get("inputConfig") or {}
    for uri in _list(dig(src, "gcsSource", "uris")) + [dig(src, "bigquerySource", "inputUri")]:
        out.add(_data_ref(uri), EdgeType.REFERENCES, "READS_FROM")
    dst = d.get("outputConfig") or {}
    for uri in (
        dig(dst, "gcsDestination", "outputUriPrefix"),
        dig(dst, "bigqueryDestination", "outputUri"),
    ):
        out.add(_data_ref(uri), EdgeType.REFERENCES, "WRITES_TO")
    out.sa(d.get("serviceAccount"), ctx, "prediction job identity")


@_extractor("aiplatform.googleapis.com/TuningJob")
def _model_tuning(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    spec = d.get("supervisedTuningSpec") or {}
    for key in ("trainingDatasetUri", "validationDatasetUri"):
        out.add(_data_ref(spec.get(key)), EdgeType.REFERENCES, "READS_FROM")
    out.add(full_name(dig(d, "tunedModel", "model"), _AI), EdgeType.REFERENCES, "WRITES_TO")
    out.sa(d.get("serviceAccount"), ctx, "tuning identity")
    out.metadata["base_model"] = d.get("baseModel")


# ---------------------------------------------------------------------------
# Feature Store, datasets, Colab Enterprise
# ---------------------------------------------------------------------------


@_extractor("aiplatform.googleapis.com/FeatureGroup")
def _feature_group(ctx: GCPContext, out: Extracted) -> None:
    out.add(
        _data_ref(dig(ctx.data, "bigQuery", "bigQuerySource", "inputUri")),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="feature source table",
    )


@_extractor("aiplatform.googleapis.com/FeatureOnlineStore")
def _feature_online_store(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    endpoint = d.get("dedicatedServingEndpoint") or {}
    psc = endpoint.get("privateServiceConnectConfig") or {}
    for project in _list(psc.get("projectAllowlist")):
        out.add(
            f"//cloudresourcemanager.googleapis.com/projects/{project}",
            EdgeType.GRANTS_ACCESS,
            "CROSS_ACCOUNT_TRUST",
            reverse=True,
        )
    domain = endpoint.get("publicEndpointDomainName")
    if domain and not psc.get("enablePrivateServiceConnect"):
        out.expose("Feature online store public endpoint", protocol="tcp", ports=["443"])
    out.metadata.update(
        storage="bigtable" if d.get("bigtable") else "optimized" if d.get("optimized") else None,
        public_endpoint=domain,
    )


@_extractor("aiplatform.googleapis.com/Featurestore")
def _featurestore(ctx: GCPContext, out: Extracted) -> None:
    out.metadata["online_serving_nodes"] = dig(ctx.data, "onlineServingConfig", "fixedNodeCount")


@_extractor("aiplatform.googleapis.com/Dataset")
def _vertex_dataset(ctx: GCPContext, out: Extracted) -> None:
    md = ctx.data.get("metadata") or {}
    src = md.get("inputConfig") or {}
    for uri in _list(dig(src, "gcsSource", "uri")) + [dig(src, "bigquerySource", "uri")]:
        out.add(_data_ref(uri), EdgeType.REFERENCES, "READS_FROM")
    out.metadata["schema"] = str(ctx.data.get("metadataSchemaUri") or "").rsplit("/", 1)[-1] or None


@_extractor("aiplatform.googleapis.com/NotebookRuntimeTemplate")
def _runtime_template(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    net = d.get("networkSpec") or {}
    out.in_subnet(full_name(net.get("subnetwork") or net.get("network"), "compute"))
    out.sa(d.get("serviceAccount"), ctx, "runtime identity")
    out.metadata.update(
        internet_access=net.get("enableInternetAccess"),
        machine_type=dig(d, "machineSpec", "machineType"),
    )


@_extractor("aiplatform.googleapis.com/NotebookRuntime")
def _runtime(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(dig(d, "notebookRuntimeTemplateRef", "notebookRuntimeTemplate"), _AI),
        EdgeType.REFERENCES,
        "DEPENDS_ON",
    )
    out.sa(d.get("serviceAccount"), ctx, "runtime identity")
    out.metadata.update(runtime_state=d.get("runtimeState"), health=d.get("healthState"))
