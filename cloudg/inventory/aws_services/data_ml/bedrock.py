"""Bedrock: agents (action group Lambdas, knowledge bases, guardrails),
knowledge bases (vector stores, data sources), guardrails and model
invocation logging."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import rel
from cloudg.inventory.aws_services.data_ml._common import (
    _AGENT_VERSION,
    DataMLHelpersMixin,
    Relations,
    _bucket_arn,
    _gather_details,
    _host,
    _kms_ref,
    logger,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# Knowledge base storage configuration block -> field naming the vector store
_KB_STORE_TARGETS = {
    "opensearchServerlessConfiguration": "collectionArn",
    "opensearchManagedClusterConfiguration": "domainArn",
    "rdsConfiguration": "resourceArn",
    "neptuneAnalyticsConfiguration": "graphArn",
    "s3VectorsConfiguration": "vectorBucketArn",
}


def _secret_rel(block: dict, description: str) -> dict[str, Any] | None:
    return rel(
        block.get("credentialsSecretArn"),
        EdgeType.REFERENCES,
        "READS_FROM",
        description=description,
    )


def _action_group_rels(groups: list[dict]) -> Relations:
    """Executor Lambdas and S3 API schemas of an agent's action groups."""
    relations: Relations = []
    for g in groups:
        executor = g.get("actionGroupExecutor") or {}
        relations.append(
            rel(
                executor.get("lambda"),
                EdgeType.INVOKES,
                "INVOKES",
                description="action group executor",
                action_group=g.get("actionGroupName"),
            )
        )
        schema_s3 = (g.get("apiSchema") or {}).get("s3") or {}
        if schema_s3.get("s3BucketName"):
            relations.append(
                rel(
                    f"arn:aws:s3:::{schema_s3['s3BucketName']}",
                    EdgeType.REFERENCES,
                    "READS_FROM",
                    description="action group API schema",
                )
            )
    return relations


def _kb_store_rels(storage: dict) -> tuple[Relations, list[str]]:
    """Vector store relations and endpoint hosts of a knowledge base."""
    relations: Relations = []
    endpoints: list[str] = []
    for key, field in _KB_STORE_TARGETS.items():
        block = storage.get(key) or {}
        relations.append(
            rel(
                block.get(field),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="vector store",
                store_type=storage.get("type"),
            )
        )
    for block in storage.values():
        if not isinstance(block, dict):
            continue
        relations.append(_secret_rel(block, "vector store credentials"))
        for field in ("connectionString", "endpoint", "domainEndpoint"):
            host = _host(block.get(field))
            if host:
                endpoints.append(host)
    return relations, endpoints


def _kb_source_rels(ds: dict) -> tuple[Relations, dict[str, Any]]:
    """Relations and metadata summary of one knowledge base data source."""
    cfg = ds.get("dataSourceConfiguration") or {}
    s3cfg = cfg.get("s3Configuration") or {}
    relations: Relations = [
        rel(
            s3cfg.get("bucketArn"),
            EdgeType.REFERENCES,
            "READS_FROM",
            description="knowledge base data source",
            data_source=ds.get("name"),
        ),
        rel(
            _kms_ref((ds.get("serverSideEncryptionConfiguration") or {}).get("kmsKeyArn")),
            EdgeType.REFERENCES,
            "ENCRYPTED_BY_KMS",
        ),
    ]
    hosts = []
    for block in cfg.values():
        if isinstance(block, dict):
            src = block.get("sourceConfiguration") or {}
            relations.append(_secret_rel(src, "data source credentials"))
            hosts.append(_host(src.get("hostUrl")))
    meta = {
        "name": ds.get("name"),
        "type": cfg.get("type"),
        "status": ds.get("status"),
        "hosts": [h for h in hosts if h],
    }
    return relations, meta


class BedrockCollectorsMixin(DataMLHelpersMixin):
    """Bedrock collectors."""

    async def _collect_bedrock(self) -> list[CloudAsset]:
        async with (
            self._client("bedrock-agent") as agent_client,
            self._client("bedrock") as bedrock,
        ):
            return await self._gather_parts(
                "bedrock",
                {
                    "agents": lambda: self._bedrock_agents(agent_client),
                    "knowledge_bases": lambda: self._bedrock_knowledge_bases(agent_client),
                    "guardrails": lambda: self._bedrock_guardrails(bedrock),
                    "invocation_logging": lambda: self._bedrock_invocation_logging(bedrock),
                },
            )

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    async def _bedrock_agents(self, ba: Any) -> list[CloudAsset]:
        summaries = [s async for s in self._paginate(ba, "list_agents", "agentSummaries")]
        return await _gather_details(summaries, lambda s: self._bedrock_agent(ba, s))

    async def _agent_action_groups(self, ba: Any, agent_id: str) -> list[dict]:
        out: list[dict] = []
        try:
            async for ag in self._paginate(
                ba,
                "list_agent_action_groups",
                "actionGroupSummaries",
                agentId=agent_id,
                agentVersion=_AGENT_VERSION,
            ):
                try:
                    resp = await ba.get_agent_action_group(
                        agentId=agent_id,
                        agentVersion=_AGENT_VERSION,
                        actionGroupId=ag["actionGroupId"],
                    )
                    out.append(resp.get("agentActionGroup") or {})
                except Exception as exc:
                    logger.debug("Action group lookup failed: %s", exc)
        except Exception as exc:
            logger.debug("Action group listing failed for agent %s: %s", agent_id, exc)
        return out

    async def _agent_knowledge_bases(self, ba: Any, agent_id: str) -> list[dict]:
        try:
            return [
                kb
                async for kb in self._paginate(
                    ba,
                    "list_agent_knowledge_bases",
                    "agentKnowledgeBaseSummaries",
                    agentId=agent_id,
                    agentVersion=_AGENT_VERSION,
                )
            ]
        except Exception as exc:
            logger.debug("Agent knowledge base listing failed for %s: %s", agent_id, exc)
            return []

    def _agent_kb_rels(self, kbs: list[dict]) -> Relations:
        return [
            rel(
                self._arn("bedrock", f"knowledge-base/{kb['knowledgeBaseId']}"),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="agent knowledge base",
                state=kb.get("knowledgeBaseState"),
            )
            for kb in kbs
            if kb.get("knowledgeBaseId")
        ]

    async def _bedrock_agent(self, ba: Any, summary: dict) -> CloudAsset:
        agent_id = summary["agentId"]
        a = (await ba.get_agent(agentId=agent_id)).get("agent") or {}
        kms = _kms_ref(a.get("customerEncryptionKeyArn"))
        guardrail = a.get("guardrailConfiguration") or summary.get("guardrailConfiguration") or {}
        relations: Relations = [
            rel(a.get("agentResourceRoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
            rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
            rel(
                guardrail.get("guardrailIdentifier"),
                EdgeType.PROTECTS,
                reverse=True,
                description="Bedrock guardrail",
                version=guardrail.get("guardrailVersion"),
            ),
        ]
        groups = await self._agent_action_groups(ba, agent_id)
        relations += _action_group_rels(groups)
        kbs = await self._agent_knowledge_bases(ba, agent_id)
        relations += self._agent_kb_rels(kbs)
        return self._asset(
            arn=a.get("agentArn") or self._arn("bedrock", f"agent/{agent_id}"),
            name=a.get("agentName") or summary.get("agentName") or agent_id,
            asset_type=AssetType.AI_AGENT,
            metadata={
                "service": "bedrock",
                "agent_id": agent_id,
                "status": a.get("agentStatus") or summary.get("agentStatus"),
                "foundation_model": a.get("foundationModel"),
                "orchestration": a.get("orchestrationType"),
                "collaboration": a.get("agentCollaboration"),
                "kms_key_id": kms,
                "guardrail": guardrail.get("guardrailIdentifier"),
                "action_groups": [g.get("actionGroupName") for g in groups],
                "action_group_lambdas": [
                    (g.get("actionGroupExecutor") or {}).get("lambda")
                    for g in groups
                    if (g.get("actionGroupExecutor") or {}).get("lambda")
                ],
                "knowledge_bases": [kb.get("knowledgeBaseId") for kb in kbs],
            },
            relations=relations,
            aliases=[agent_id],
        )

    # ------------------------------------------------------------------
    # Knowledge bases
    # ------------------------------------------------------------------

    async def _bedrock_knowledge_bases(self, ba: Any) -> list[CloudAsset]:
        summaries = [
            s async for s in self._paginate(ba, "list_knowledge_bases", "knowledgeBaseSummaries")
        ]
        return await _gather_details(summaries, lambda s: self._bedrock_knowledge_base(ba, s))

    async def _kb_data_sources(self, ba: Any, kb_id: str) -> list[dict]:
        out: list[dict] = []
        try:
            async for ds in self._paginate(
                ba, "list_data_sources", "dataSourceSummaries", knowledgeBaseId=kb_id
            ):
                try:
                    resp = await ba.get_data_source(
                        knowledgeBaseId=kb_id, dataSourceId=ds["dataSourceId"]
                    )
                    out.append(resp.get("dataSource") or {})
                except Exception as exc:
                    logger.debug("Data source lookup failed: %s", exc)
                    out.append(ds)
        except Exception as exc:
            logger.debug("Data source listing failed for %s: %s", kb_id, exc)
        return out

    @staticmethod
    def _kb_config_rels(config: dict, vector: dict) -> Relations:
        """Kendra index and supplemental data storage of a knowledge base."""
        relations: Relations = [
            rel(
                (config.get("kendraKnowledgeBaseConfiguration") or {}).get("kendraIndexArn"),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="Kendra index",
            )
        ]
        for loc in (vector.get("supplementalDataStorageConfiguration") or {}).get(
            "storageLocations"
        ) or []:
            relations.append(
                rel(
                    _bucket_arn((loc.get("s3Location") or {}).get("uri")),
                    EdgeType.REFERENCES,
                    "WRITES_TO",
                    description="supplemental data storage",
                )
            )
        return relations

    async def _bedrock_knowledge_base(self, ba: Any, summary: dict) -> CloudAsset:
        kb_id = summary["knowledgeBaseId"]
        kb = (await ba.get_knowledge_base(knowledgeBaseId=kb_id)).get("knowledgeBase") or {}
        storage = kb.get("storageConfiguration") or {}
        config = kb.get("knowledgeBaseConfiguration") or {}
        vector = config.get("vectorKnowledgeBaseConfiguration") or {}
        relations: Relations = [rel(kb.get("roleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON")]
        store_rels, endpoints = _kb_store_rels(storage)
        relations += store_rels
        relations += self._kb_config_rels(config, vector)
        source_meta = []
        for ds in await self._kb_data_sources(ba, kb_id):
            source_rels, meta = _kb_source_rels(ds)
            relations += source_rels
            source_meta.append(meta)
        return self._asset(
            arn=kb.get("knowledgeBaseArn") or self._arn("bedrock", f"knowledge-base/{kb_id}"),
            name=kb.get("name") or summary.get("name") or kb_id,
            asset_type=AssetType.KNOWLEDGE_BASE,
            metadata={
                "service": "bedrock",
                "knowledge_base_id": kb_id,
                "status": kb.get("status"),
                "type": config.get("type"),
                "storage_type": storage.get("type"),
                "embedding_model": vector.get("embeddingModelArn"),
                "vector_store_endpoints": sorted(set(endpoints)),
                "data_sources": source_meta,
            },
            relations=relations,
            aliases=[kb_id],
        )

    # ------------------------------------------------------------------
    # Guardrails / invocation logging
    # ------------------------------------------------------------------

    async def _bedrock_guardrails(self, bedrock: Any) -> list[CloudAsset]:
        guardrails = [g async for g in self._paginate(bedrock, "list_guardrails", "guardrails")]
        return await _gather_details(guardrails, lambda g: self._bedrock_guardrail(bedrock, g))

    async def _bedrock_guardrail(self, bedrock: Any, g: dict) -> CloudAsset:
        full: dict = {}
        try:
            full = await bedrock.get_guardrail(guardrailIdentifier=g["id"])
        except Exception as exc:
            logger.debug("Guardrail lookup failed for %s: %s", g.get("id"), exc)
        kms = _kms_ref(full.get("kmsKeyArn"))
        return self._asset(
            arn=g.get("arn") or self._arn("bedrock", f"guardrail/{g['id']}"),
            name=g.get("name") or g["id"],
            asset_type=AssetType.AI_GUARDRAIL,
            metadata={
                "service": "bedrock",
                "guardrail_id": g.get("id"),
                "status": g.get("status"),
                "version": g.get("version"),
                "kms_key_id": kms,
                "topic_policy": bool(full.get("topicPolicy")),
                "content_policy": bool(full.get("contentPolicy")),
                "word_policy": bool(full.get("wordPolicy")),
                "sensitive_information_policy": bool(full.get("sensitiveInformationPolicy")),
                "contextual_grounding_policy": bool(full.get("contextualGroundingPolicy")),
                "cross_region_profile": (g.get("crossRegionDetails") or {}).get(
                    "guardrailProfileArn"
                ),
            },
            relations=[rel(kms, EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")],
            aliases=[g.get("id")],
        )

    async def _bedrock_invocation_logging(self, bedrock: Any) -> list[CloudAsset]:
        """Model invocation logging is a region-wide setting, so it becomes
        one LOG_SINK asset per region (only when configured)."""
        cfg = (await bedrock.get_model_invocation_logging_configuration()).get(
            "loggingConfig"
        ) or {}
        if not cfg:
            return []
        cw = cfg.get("cloudWatchConfig") or {}
        s3 = cfg.get("s3Config") or {}
        large = cw.get("largeDataDeliveryS3Config") or {}
        relations: Relations = [
            rel(self._log_group_ref(cw.get("logGroupName")), EdgeType.LOGS_TO, "LOGS_TO"),
            rel(cw.get("roleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
        ]
        for bucket in (s3.get("bucketName"), large.get("bucketName")):
            if bucket:
                relations.append(rel(f"arn:aws:s3:::{bucket}", EdgeType.LOGS_TO, "LOGS_TO"))
        return [
            self._asset(
                arn=f"cloudg:aws:bedrock:{self._region}:{self._account_id}:model-invocation-logging",
                name=f"Bedrock model invocation logging ({self._region})",
                asset_type=AssetType.LOG_SINK,
                metadata={
                    "service": "bedrock",
                    "kind": "model_invocation_logging",
                    "log_group": cw.get("logGroupName"),
                    "s3_bucket": s3.get("bucketName"),
                    "text": cfg.get("textDataDeliveryEnabled"),
                    "image": cfg.get("imageDataDeliveryEnabled"),
                    "embedding": cfg.get("embeddingDataDeliveryEnabled"),
                    "video": cfg.get("videoDataDeliveryEnabled"),
                },
                relations=relations,
            )
        ]
