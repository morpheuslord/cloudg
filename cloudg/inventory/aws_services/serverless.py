"""Serverless and integration services: the event-driven wiring.

- Lambda: execution role, VPC, layers, container image (-> ECR), DLQ,
  KMS key, EFS access points, environment ARNs, event source mappings
  (SQS/Kinesis/DynamoDB/MSK -> function), resource-policy invokers
  (S3/SNS/EventBridge/API Gateway/logs -> function), function URLs.
- API Gateway REST and HTTP APIs -> Lambda / HTTP / VPC-link integrations.
- SQS queues (DLQ redrive, encryption, cross-account grants).
- SNS topics -> subscriptions (SQS, Lambda, Firehose, HTTP, email counts).
- EventBridge buses and rules -> targets (+ target roles).
- Step Functions state machines -> every resource their definition calls.
- Kinesis data streams.
"""

from __future__ import annotations

import json
import logging
import re

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    resource_policy_relations,
    arns_in,
    error_code,
    gather_limited,
    identifier_refs,
    rel,
)
from cloudg.inventory.aws_services.containers import image_repository
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

logger = logging.getLogger(__name__)

_APIGW_LAMBDA_RE = re.compile(r"functions/(arn:aws[^/]+)/invocations")


_resource_policy_relations = resource_policy_relations  # backward-compatible alias


class ServerlessCollectorsMixin(AWSServiceMixin):
    # ------------------------------------------------------------------
    # Lambda (overrides the shallow base collector)
    # ------------------------------------------------------------------

    async def _collect_lambda(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("lambda") as lam:
            functions = [f async for f in self._paginate(lam, "list_functions", "Functions")]

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

            async def detail(fn: dict) -> CloudAsset:
                name = fn.get("FunctionName", "")
                arn = fn.get("FunctionArn", "")
                relations: list[dict | None] = [
                    rel(
                        fn.get("Role"),
                        EdgeType.ASSUMES_ROLE,
                        "RUNS_ON",
                        description="execution role",
                    ),
                    rel(fn.get("KMSKeyArn"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS"),
                    rel(
                        (fn.get("DeadLetterConfig") or {}).get("TargetArn"),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="dead-letter target",
                    ),
                ]
                for layer in fn.get("Layers", []) or []:
                    relations.append(
                        rel(
                            layer.get("Arn"), EdgeType.REFERENCES, "DEPENDS_ON", description="layer"
                        )
                    )
                for fs in fn.get("FileSystemConfigs", []) or []:
                    relations.append(
                        rel(
                            fs.get("Arn"),
                            EdgeType.REFERENCES,
                            "READS_FROM",
                            description="EFS mount",
                        )
                    )
                env = (fn.get("Environment") or {}).get("Variables") or {}
                for ref in identifier_refs(env):
                    relations.append(
                        rel(
                            ref,
                            EdgeType.REFERENCES,
                            "DEPENDS_ON",
                            description="environment reference",
                        )
                    )
                log_group = (fn.get("LoggingConfig") or {}).get("LogGroup") or f"/aws/lambda/{name}"
                relations.append(
                    rel(self._arn("logs", f"log-group:{log_group}"), EdgeType.LOGS_TO, "LOGS_TO")
                )

                image_uri = None
                if fn.get("PackageType") == "Image":
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

                for esm in mappings.get(name, []):
                    src = esm.get("EventSourceArn")
                    relations.append(
                        rel(
                            src,
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

                url_auth = None
                try:
                    url_cfg = await lam.get_function_url_config(FunctionName=name)
                    url_auth = url_cfg.get("AuthType")
                except Exception as exc:
                    if error_code(exc) != "ResourceNotFoundException":
                        logger.debug("Function URL lookup failed for %s: %s", name, exc)

                public_policy = False
                try:
                    pol = await lam.get_policy(FunctionName=name)
                    pol_rels, public_policy = _resource_policy_relations(
                        pol.get("Policy"), self._account_id
                    )
                    relations.extend(pol_rels)
                except Exception as exc:
                    if error_code(exc) != "ResourceNotFoundException":
                        logger.debug("Lambda policy read failed for %s: %s", name, exc)

                exposed = url_auth == "NONE" or public_policy
                return self._asset(
                    arn=arn,
                    name=name,
                    asset_type=AssetType.LAMBDA_FUNCTION,
                    metadata={
                        "runtime": fn.get("Runtime"),
                        "handler": fn.get("Handler"),
                        "package_type": fn.get("PackageType", "Zip"),
                        "image_uri": image_uri,
                        "architectures": fn.get("Architectures", []),
                        "memory_size": fn.get("MemorySize"),
                        "timeout": fn.get("Timeout"),
                        "last_modified": fn.get("LastModified"),
                        "vpc_config": fn.get("VpcConfig"),
                        "role_arn": fn.get("Role"),
                        "environment_keys": sorted(env),
                        "layers": [layer.get("Arn") for layer in fn.get("Layers", []) or []],
                        "event_sources": [m.get("EventSourceArn") for m in mappings.get(name, [])],
                        "function_url_auth": url_auth,
                        "policy_allows_public": public_policy,
                        "tracing": (fn.get("TracingConfig") or {}).get("Mode"),
                    },
                    relations=relations,
                    raw={k: v for k, v in fn.items() if k != "Environment"},
                    exposed=exposed,
                    aliases=[f"{arn}:$LATEST"],
                )

            results = await gather_limited([lambda f=f: detail(f) for f in functions])
            assets.extend(a for a in results if a)
        return assets

    # ------------------------------------------------------------------
    # API Gateway
    # ------------------------------------------------------------------

    async def _collect_apigateway(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("apigateway") as apigw:
            apis = [a async for a in self._paginate(apigw, "get_rest_apis", "items")]
            for api in apis:
                api_id = api["id"]
                relations: list[dict | None] = []
                integrations: list[dict] = []
                try:
                    async for res in self._paginate(
                        apigw, "get_resources", "items", restApiId=api_id, embed=["methods"]
                    ):
                        for method, spec in (res.get("resourceMethods") or {}).items():
                            integ = (spec or {}).get("methodIntegration") or {}
                            uri = integ.get("uri") or ""
                            m = _APIGW_LAMBDA_RE.search(uri)
                            target = m.group(1) if m else None
                            if target:
                                relations.append(
                                    rel(
                                        target,
                                        EdgeType.INVOKES,
                                        "INVOKES",
                                        description=f"{method} {res.get('path')}",
                                    )
                                )
                            if integ.get("connectionId"):
                                relations.append(
                                    rel(
                                        integ["connectionId"],
                                        EdgeType.ROUTE,
                                        "SERVES_TRAFFIC_TO",
                                        description="VPC link",
                                    )
                                )
                            integrations.append(
                                {
                                    "path": res.get("path"),
                                    "method": method,
                                    "type": integ.get("type"),
                                    "auth": (spec or {}).get("authorizationType"),
                                    "target": target or (uri if uri.startswith("http") else None),
                                }
                            )
                except Exception as exc:
                    logger.debug("API Gateway resource listing failed for %s: %s", api_id, exc)
                stages: list[str] = []
                try:
                    resp = await apigw.get_stages(restApiId=api_id)
                    for stage in resp.get("item", []):
                        stages.append(stage.get("stageName"))
                        relations.append(
                            rel(
                                stage.get("webAclArn"),
                                EdgeType.PROTECTS,
                                "PROTECTED_BY_WAF",
                                reverse=True,
                            )
                        )
                        dest = (stage.get("accessLogSettings") or {}).get("destinationArn")
                        relations.append(rel(dest, EdgeType.LOGS_TO, "LOGS_TO"))
                except Exception as exc:
                    logger.debug("API Gateway stage listing failed for %s: %s", api_id, exc)
                endpoint_types = (api.get("endpointConfiguration") or {}).get("types", [])
                pol_rels, _ = _resource_policy_relations(api.get("policy"), self._account_id)
                assets.append(
                    self._asset(
                        arn=f"arn:aws:apigateway:{self._region}::/restapis/{api_id}",
                        name=api.get("name", api_id),
                        asset_type=AssetType.API_GATEWAY,
                        tags=api.get("tags"),
                        metadata={
                            "api_type": "REST",
                            "api_id": api_id,
                            "endpoint_types": endpoint_types,
                            "stages": stages,
                            "integrations": integrations[:200],
                            "unauthenticated_methods": sum(
                                1 for i in integrations if i.get("auth") == "NONE"
                            ),
                        },
                        relations=relations + pol_rels,
                        exposed="PRIVATE" not in endpoint_types,
                        aliases=[api_id],
                    )
                )
        return assets

    async def _collect_apigatewayv2(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("apigatewayv2") as apigw:
            apis = [a async for a in self._paginate(apigw, "get_apis", "Items")]
            for api in apis:
                api_id = api["ApiId"]
                relations: list[dict | None] = []
                try:
                    async for integ in self._paginate(
                        apigw, "get_integrations", "Items", ApiId=api_id
                    ):
                        uri = integ.get("IntegrationUri") or ""
                        m = _APIGW_LAMBDA_RE.search(uri)
                        target = m.group(1) if m else uri
                        if target.startswith("arn:"):
                            relations.append(
                                rel(
                                    target,
                                    EdgeType.INVOKES,
                                    "INVOKES",
                                    description=integ.get("IntegrationType"),
                                )
                            )
                        if integ.get("ConnectionId"):
                            relations.append(
                                rel(
                                    integ["ConnectionId"],
                                    EdgeType.ROUTE,
                                    "SERVES_TRAFFIC_TO",
                                    description="VPC link",
                                )
                            )
                        relations.append(
                            rel(integ.get("CredentialsArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON")
                        )
                except Exception as exc:
                    logger.debug("HTTP API integration listing failed for %s: %s", api_id, exc)
                assets.append(
                    self._asset(
                        arn=f"arn:aws:apigateway:{self._region}::/apis/{api_id}",
                        name=api.get("Name", api_id),
                        asset_type=AssetType.API_GATEWAY,
                        tags=api.get("Tags"),
                        metadata={
                            "api_type": api.get("ProtocolType"),
                            "api_id": api_id,
                            "endpoint": api.get("ApiEndpoint"),
                            "default_endpoint_disabled": api.get(
                                "DisableExecuteApiEndpoint", False
                            ),
                        },
                        relations=relations,
                        exposed=not api.get("DisableExecuteApiEndpoint", False),
                        aliases=[api_id, api.get("ApiEndpoint")],
                    )
                )
        return assets

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    async def _collect_sqs(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("sqs") as sqs:
            # ListQueues only returns a NextToken when MaxResults is set.
            urls = [
                u
                async for u in self._paginate(
                    sqs, "list_queues", "QueueUrls", PaginationConfig={"PageSize": 1000}
                )
            ]

            async def detail(url: str) -> CloudAsset:
                attrs = (await sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])).get(
                    "Attributes", {}
                )
                arn = attrs.get("QueueArn", url)
                relations: list[dict | None] = [
                    rel(attrs.get("KmsMasterKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
                ]
                redrive = json.loads(attrs["RedrivePolicy"]) if attrs.get("RedrivePolicy") else {}
                relations.append(
                    rel(
                        redrive.get("deadLetterTargetArn"),
                        EdgeType.REFERENCES,
                        "WRITES_TO",
                        description="dead-letter queue",
                    )
                )
                pol_rels, public = _resource_policy_relations(attrs.get("Policy"), self._account_id)
                relations.extend(pol_rels)
                return self._asset(
                    arn=arn,
                    name=arn.rsplit(":", 1)[-1],
                    asset_type=AssetType.MESSAGE_QUEUE,
                    metadata={
                        "queue_url": url,
                        "fifo": attrs.get("FifoQueue") == "true",
                        "kms_key_id": attrs.get("KmsMasterKeyId"),
                        "sse_sqs": attrs.get("SqsManagedSseEnabled") == "true",
                        "visibility_timeout": attrs.get("VisibilityTimeout"),
                        "dead_letter_target": redrive.get("deadLetterTargetArn"),
                        "policy_allows_public": public,
                    },
                    relations=relations,
                    exposed=public,
                    aliases=[url],
                )

            results = await gather_limited([lambda u=u: detail(u) for u in urls])
            assets.extend(a for a in results if a)
        return assets

    async def _collect_sns(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("sns") as sns:
            topics = [t["TopicArn"] async for t in self._paginate(sns, "list_topics", "Topics")]
            subs: dict[str, list[dict]] = {}
            try:
                async for s in self._paginate(sns, "list_subscriptions", "Subscriptions"):
                    subs.setdefault(s.get("TopicArn", ""), []).append(s)
            except Exception as exc:
                logger.debug("SNS subscription listing failed: %s", exc)

            async def detail(arn: str) -> CloudAsset:
                attrs = (await sns.get_topic_attributes(TopicArn=arn)).get("Attributes", {})
                relations: list[dict | None] = [
                    rel(attrs.get("KmsMasterKeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
                ]
                protocols: dict[str, int] = {}
                for s in subs.get(arn, []):
                    proto = s.get("Protocol", "")
                    protocols[proto] = protocols.get(proto, 0) + 1
                    if proto in ("sqs", "lambda", "firehose", "application"):
                        relations.append(
                            rel(
                                s.get("Endpoint"),
                                EdgeType.INVOKES,
                                "STREAMS_TO",
                                description=f"{proto} subscription",
                            )
                        )
                pol_rels, public = _resource_policy_relations(attrs.get("Policy"), self._account_id)
                relations.extend(pol_rels)
                return self._asset(
                    arn=arn,
                    name=arn.rsplit(":", 1)[-1],
                    asset_type=AssetType.NOTIFICATION_TOPIC,
                    metadata={
                        "kms_key_id": attrs.get("KmsMasterKeyId"),
                        "subscriptions_by_protocol": protocols,
                        "fifo": attrs.get("FifoTopic") == "true",
                        "policy_allows_public": public,
                    },
                    relations=relations,
                    exposed=public,
                )

            results = await gather_limited([lambda t=t: detail(t) for t in topics])
            assets.extend(a for a in results if a)
        return assets

    async def _collect_eventbridge(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("events") as events:
            buses = [b async for b in self._pages(events.list_event_buses, "EventBuses")]
            for bus in buses:
                bus_name = bus.get("Name", "default")
                pol_rels, public = _resource_policy_relations(bus.get("Policy"), self._account_id)
                assets.append(
                    self._asset(
                        arn=bus["Arn"],
                        name=bus_name,
                        asset_type=AssetType.EVENT_BUS,
                        metadata={"policy_allows_public": public},
                        relations=pol_rels,
                        exposed=public,
                    )
                )
                async for rule in self._paginate(
                    events, "list_rules", "Rules", EventBusName=bus_name
                ):
                    relations: list[dict | None] = [
                        rel(bus["Arn"], EdgeType.CONTAINS, reverse=True),
                        rel(rule.get("RoleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                    ]
                    targets: list[str] = []
                    try:
                        async for t in self._paginate(
                            events,
                            "list_targets_by_rule",
                            "Targets",
                            Rule=rule["Name"],
                            EventBusName=bus_name,
                        ):
                            targets.append(t.get("Arn", ""))
                            relations.append(
                                rel(
                                    t.get("Arn"),
                                    EdgeType.INVOKES,
                                    "INVOKES",
                                    description=f"target {t.get('Id')}",
                                )
                            )
                            relations.append(
                                rel(
                                    t.get("RoleArn"),
                                    EdgeType.ASSUMES_ROLE,
                                    "RUNS_ON",
                                    description="target role",
                                )
                            )
                            dlq = (t.get("DeadLetterConfig") or {}).get("Arn")
                            relations.append(
                                rel(dlq, EdgeType.REFERENCES, "WRITES_TO", description="target DLQ")
                            )
                    except Exception as exc:
                        logger.debug("Target listing failed for %s: %s", rule.get("Name"), exc)
                    assets.append(
                        self._asset(
                            arn=rule["Arn"],
                            name=rule["Name"],
                            asset_type=AssetType.EVENT_RULE,
                            metadata={
                                "event_bus": bus_name,
                                "state": rule.get("State"),
                                "schedule": rule.get("ScheduleExpression"),
                                "event_pattern": rule.get("EventPattern"),
                                "managed_by": rule.get("ManagedBy"),
                                "targets": targets,
                            },
                            relations=relations,
                        )
                    )
        return assets

    async def _collect_stepfunctions(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("stepfunctions") as sfn:
            machines = [
                m async for m in self._paginate(sfn, "list_state_machines", "stateMachines")
            ]

            async def detail(sm: dict) -> CloudAsset:
                desc = await sfn.describe_state_machine(stateMachineArn=sm["stateMachineArn"])
                definition = desc.get("definition") or "{}"
                try:
                    parsed = json.loads(definition)
                except ValueError:
                    parsed = {}
                called = [a for a in arns_in(parsed) if not a.startswith("arn:aws:states:::")]
                relations: list[dict | None] = [
                    rel(desc.get("roleArn"), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
                ]
                relations += [
                    rel(a, EdgeType.INVOKES, "INVOKES", description="called by definition")
                    for a in called
                ]
                for dest in (desc.get("loggingConfiguration") or {}).get("destinations", []) or []:
                    group = (
                        (dest.get("cloudWatchLogsLogGroup") or {}).get("logGroupArn") or ""
                    ).removesuffix(":*")
                    relations.append(rel(group, EdgeType.LOGS_TO, "LOGS_TO"))
                integrations = sorted(
                    {
                        a.split(":::", 1)[1].split(".", 1)[0]
                        for a in arns_in(parsed)
                        if a.startswith("arn:aws:states:::")
                    }
                )
                return self._asset(
                    arn=sm["stateMachineArn"],
                    name=sm.get("name", ""),
                    asset_type=AssetType.STATE_MACHINE,
                    metadata={
                        "type": desc.get("type"),
                        "status": desc.get("status"),
                        "service_integrations": integrations,
                        "states": len((parsed.get("States") or {})),
                        "role_arn": desc.get("roleArn"),
                    },
                    relations=relations,
                )

            results = await gather_limited([lambda m=m: detail(m) for m in machines])
            assets.extend(a for a in results if a)
        return assets

    async def _collect_kinesis(self) -> list[CloudAsset]:
        assets: list[CloudAsset] = []
        async with self._client("kinesis") as kinesis:
            names = [n async for n in self._paginate(kinesis, "list_streams", "StreamNames")]

            async def detail(name: str) -> CloudAsset:
                s = (await kinesis.describe_stream_summary(StreamName=name))[
                    "StreamDescriptionSummary"
                ]
                return self._asset(
                    arn=s["StreamARN"],
                    name=name,
                    asset_type=AssetType.DATA_STREAM,
                    metadata={
                        "status": s.get("StreamStatus"),
                        "mode": (s.get("StreamModeDetails") or {}).get("StreamMode"),
                        "shards": s.get("OpenShardCount"),
                        "encryption": s.get("EncryptionType"),
                        "kms_key_id": s.get("KeyId"),
                        "consumers": s.get("ConsumerCount"),
                    },
                    relations=[rel(s.get("KeyId"), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")],
                )

            results = await gather_limited([lambda n=n: detail(n) for n in names])
            assets.extend(a for a in results if a)
        return assets
