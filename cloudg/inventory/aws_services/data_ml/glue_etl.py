"""Glue ETL: jobs, crawlers, connections and triggers."""

from __future__ import annotations

from typing import Any, Callable

from cloudg.inventory.aws_services._base import identifier_refs, rel
from cloudg.inventory.aws_services.data_ml._common import (
    _GLUE_ARG_LOGS,
    _GLUE_ARG_READS,
    _GLUE_ARG_WRITES,
    DataMLHelpersMixin,
    Relations,
    _bucket_arn,
    _host,
    _kms_ref,
)
from cloudg.schema.models import AssetType, CloudAsset, EdgeType

# Trigger action / predicate condition fields -> (Glue resource kind, state field)
_TRIGGER_REFS = (("JobName", "job", "State"), ("CrawlerName", "crawler", "CrawlState"))


def _glue_arg_rels(args: dict) -> Relations:
    """S3 locations and identifiers referenced by Glue job arguments."""
    relations: Relations = []
    for key in _GLUE_ARG_READS:
        for part in str(args.get(key, "")).split(","):
            relations.append(
                rel(_bucket_arn(part.strip()), EdgeType.REFERENCES, "READS_FROM", argument=key)
            )
    for key in _GLUE_ARG_WRITES:
        relations.append(
            rel(_bucket_arn(args.get(key)), EdgeType.REFERENCES, "WRITES_TO", argument=key)
        )
    for key in _GLUE_ARG_LOGS:
        relations.append(rel(_bucket_arn(args.get(key)), EdgeType.LOGS_TO, "LOGS_TO", argument=key))
    relations += [
        rel(r, EdgeType.REFERENCES, "DEPENDS_ON", description="job argument")
        for r in identifier_refs(args)
    ]
    return relations


def _events_rel(target: dict) -> dict[str, Any] | None:
    return rel(target.get("EventQueueArn"), EdgeType.REFERENCES, "READS_FROM", source_type="events")


def _connection_hosts(props: dict) -> list[str]:
    """Endpoint hosts named by Glue connection properties."""
    hosts: list[str] = []
    for key in ("JDBC_CONNECTION_URL", "CONNECTION_URL", "HOST"):
        host = _host(props.get(key))
        if host:
            hosts.append(host)
    for broker in str(props.get("KAFKA_BOOTSTRAP_SERVERS", "")).split(","):
        host = _host(broker.strip())
        if host:
            hosts.append(host)
    return hosts


class GlueEtlCollectorsMixin(DataMLHelpersMixin):
    """Glue job, crawler, connection and trigger collectors."""

    def _glue_arn(self, kind: str, name: str) -> str:
        return self._arn("glue", f"{kind}/{name}")

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    async def _glue_jobs(self, glue: Any, security_rels: Callable[[Any], list]) -> list[CloudAsset]:
        return [
            self._glue_job(j, security_rels) async for j in self._paginate(glue, "get_jobs", "Jobs")
        ]

    def _glue_job(self, j: dict, security_rels: Callable[[Any], list]) -> CloudAsset:
        name = j["Name"]
        command = j.get("Command") or {}
        relations: Relations = [
            rel(self._dm_role_ref(j.get("Role")), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
            rel(
                _bucket_arn(command.get("ScriptLocation")),
                EdgeType.REFERENCES,
                "READS_FROM",
                description="job script",
            ),
        ]
        relations += [
            rel(self._glue_arn("connection", c), EdgeType.REFERENCES, "DEPENDS_ON")
            for c in (j.get("Connections") or {}).get("Connections") or []
        ]
        relations += security_rels(j.get("SecurityConfiguration"))
        relations += _glue_arg_rels(j.get("DefaultArguments") or {})
        source = j.get("SourceControlDetails") or {}
        return self._asset(
            arn=self._glue_arn("job", name),
            name=name,
            asset_type=AssetType.ETL_JOB,
            metadata={
                "service": "glue",
                "kind": "job",
                "command": command.get("Name"),
                "script_location": command.get("ScriptLocation"),
                "glue_version": j.get("GlueVersion"),
                "worker_type": j.get("WorkerType"),
                "workers": j.get("NumberOfWorkers"),
                "security_configuration": j.get("SecurityConfiguration"),
                "connections": (j.get("Connections") or {}).get("Connections") or [],
                "source_control": {
                    "provider": source.get("Provider"),
                    "repository": source.get("Repository"),
                }
                if source
                else None,
            },
            relations=relations,
        )

    # ------------------------------------------------------------------
    # Crawlers
    # ------------------------------------------------------------------

    async def _glue_crawlers(
        self, glue: Any, security_rels: Callable[[Any], list]
    ) -> list[CloudAsset]:
        return [
            self._glue_crawler(c, security_rels)
            async for c in self._paginate(glue, "get_crawlers", "Crawlers")
        ]

    def _crawler_store_rels(self, targets: dict, connections: set[str]) -> Relations:
        """S3, JDBC / MongoDB and DynamoDB crawler targets."""
        relations: Relations = []
        for t in targets.get("S3Targets") or []:
            relations.append(
                rel(_bucket_arn(t.get("Path")), EdgeType.REFERENCES, "READS_FROM", source_type="s3")
            )
            relations.append(_events_rel(t))
            connections.add(t.get("ConnectionName") or "")
        for key in ("JdbcTargets", "MongoDBTargets"):
            for t in targets.get(key) or []:
                connections.add(t.get("ConnectionName") or "")
        for t in targets.get("DynamoDBTargets") or []:
            if t.get("Path"):
                table = (
                    t["Path"]
                    if t["Path"].startswith("arn:")
                    else self._arn("dynamodb", f"table/{t['Path']}")
                )
                relations.append(
                    rel(table, EdgeType.REFERENCES, "READS_FROM", source_type="dynamodb")
                )
        return relations

    def _crawler_catalog_rels(self, targets: dict, connections: set[str]) -> Relations:
        """Catalog and Delta / Iceberg / Hudi table crawler targets."""
        relations: Relations = []
        for t in targets.get("CatalogTargets") or []:
            if t.get("DatabaseName"):
                relations.append(
                    rel(
                        self._glue_arn("database", t["DatabaseName"]),
                        EdgeType.REFERENCES,
                        "READS_FROM",
                        source_type="catalog",
                    )
                )
            relations.append(_events_rel(t))
            connections.add(t.get("ConnectionName") or "")
        for key, field in (
            ("DeltaTargets", "DeltaTables"),
            ("IcebergTargets", "Paths"),
            ("HudiTargets", "Paths"),
        ):
            for t in targets.get(key) or []:
                relations += [
                    rel(_bucket_arn(p), EdgeType.REFERENCES, "READS_FROM", source_type=key)
                    for p in t.get(field) or []
                ]
                connections.add(t.get("ConnectionName") or "")
        return relations

    def _glue_crawler(self, c: dict, security_rels: Callable[[Any], list]) -> CloudAsset:
        name = c["Name"]
        targets = c.get("Targets") or {}
        relations: Relations = [
            rel(self._dm_role_ref(c.get("Role")), EdgeType.ASSUMES_ROLE, "RUNS_ON"),
            rel(
                self._glue_arn("database", c["DatabaseName"]) if c.get("DatabaseName") else None,
                EdgeType.REFERENCES,
                "WRITES_TO",
                description="crawler output database",
            ),
        ]
        relations += security_rels(c.get("CrawlerSecurityConfiguration"))
        connections: set[str] = set()
        relations += self._crawler_store_rels(targets, connections)
        relations += self._crawler_catalog_rels(targets, connections)
        relations += [
            rel(
                self._glue_arn("connection", n),
                EdgeType.REFERENCES,
                "READS_FROM",
                source_type="connection",
            )
            for n in sorted(connections)
            if n
        ]
        return self._asset(
            arn=self._glue_arn("crawler", name),
            name=name,
            asset_type=AssetType.ETL_JOB,
            metadata={
                "service": "glue",
                "kind": "crawler",
                "state": c.get("State"),
                "database": c.get("DatabaseName"),
                "schedule": (c.get("Schedule") or {}).get("ScheduleExpression"),
                "target_types": sorted(k for k, v in targets.items() if v),
                "security_configuration": c.get("CrawlerSecurityConfiguration"),
                "lake_formation_credentials": (c.get("LakeFormationConfiguration") or {}).get(
                    "UseLakeFormationCredentials"
                ),
            },
            relations=relations,
        )

    # ------------------------------------------------------------------
    # Connections / triggers
    # ------------------------------------------------------------------

    async def _glue_connections(self, glue: Any) -> list[CloudAsset]:
        return [
            self._glue_connection(c)
            async for c in self._paginate(
                glue, "get_connections", "ConnectionList", HidePassword=True
            )
        ]

    def _glue_connection(self, c: dict) -> CloudAsset:
        name = c["Name"]
        props = c.get("ConnectionProperties") or {}
        physical = c.get("PhysicalConnectionRequirements") or {}
        auth = c.get("AuthenticationConfiguration") or {}
        hosts = _connection_hosts(props)
        relations: Relations = self._subnet_rels(physical.get("SubnetId"))
        relations += [
            rel(
                secret,
                EdgeType.REFERENCES,
                "READS_FROM",
                description="connection credentials",
            )
            for secret in (auth.get("SecretArn"), props.get("SECRET_ID"))
        ]
        relations.append(
            rel(_kms_ref(auth.get("KmsKeyArn")), EdgeType.REFERENCES, "ENCRYPTED_BY_KMS")
        )
        relations += [
            rel(h, EdgeType.REFERENCES, "READS_FROM", description="connection endpoint")
            for h in sorted(set(hosts))
        ]
        return self._asset(
            arn=self._glue_arn("connection", name),
            name=name,
            asset_type=AssetType.DATA_CATALOG,
            metadata={
                "service": "glue",
                "kind": "connection",
                "connection_type": c.get("ConnectionType"),
                "hosts": sorted(set(hosts)),
                "security_groups": physical.get("SecurityGroupIdList") or [],
                "availability_zone": physical.get("AvailabilityZone"),
                "authentication_type": auth.get("AuthenticationType"),
                "enforce_ssl": props.get("JDBC_ENFORCE_SSL"),
                "status": c.get("Status"),
            },
            relations=relations,
        )

    async def _glue_triggers(self, glue: Any) -> list[CloudAsset]:
        return [
            self._glue_trigger(t) async for t in self._paginate(glue, "get_triggers", "Triggers")
        ]

    def _glue_trigger_rels(self, t: dict) -> Relations:
        """Jobs / crawlers a trigger starts, and those its predicate watches."""
        relations: Relations = []
        for action in t.get("Actions") or []:
            for field, kind, _ in _TRIGGER_REFS:
                if action.get(field):
                    relations.append(
                        rel(self._glue_arn(kind, action[field]), EdgeType.INVOKES, "INVOKES")
                    )
        for cond in (t.get("Predicate") or {}).get("Conditions") or []:
            for field, kind, state in _TRIGGER_REFS:
                if cond.get(field):
                    relations.append(
                        rel(
                            self._glue_arn(kind, cond[field]),
                            EdgeType.INVOKES,
                            "TRIGGERED_BY",
                            reverse=True,
                            state=cond.get(state),
                        )
                    )
        return relations

    def _glue_trigger(self, t: dict) -> CloudAsset:
        name = t["Name"]
        return self._asset(
            arn=self._glue_arn("trigger", name),
            name=name,
            asset_type=AssetType.EVENT_RULE,
            metadata={
                "service": "glue",
                "kind": "trigger",
                "trigger_type": t.get("Type"),
                "state": t.get("State"),
                "schedule": t.get("Schedule"),
                "workflow": t.get("WorkflowName"),
            },
            relations=self._glue_trigger_rels(t),
        )
