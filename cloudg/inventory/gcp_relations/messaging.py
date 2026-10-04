"""Pub/Sub topics and subscriptions."""

from __future__ import annotations

import re
from typing import Any

from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import (
    dig,
    full_name,
    url_alias,
)
from cloudg.schema.models import EdgeType

# ---------------------------------------------------------------------------
# Messaging and events
# ---------------------------------------------------------------------------


def _bq_dataset_from_table(table: Any) -> str | None:
    if not isinstance(table, str) or not table:
        return None
    m = re.match(r"^([^:.]+)[:.]([^.]+)\.", table)
    if m:
        return f"//bigquery.googleapis.com/projects/{m.group(1)}/datasets/{m.group(2)}"
    return None


@_extractor("pubsub.googleapis.com/Topic")
def _topic(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(dig(d, "schemaSettings", "schema"), "pubsub"), EdgeType.REFERENCES, "DEPENDS_ON"
    )
    out.metadata["message_retention"] = d.get("messageRetentionDuration")


def _subscription_exports(ctx: GCPContext, out: Extracted) -> Any:
    """BigQuery / Cloud Storage export destinations and identity; returns the bucket."""
    d = ctx.data
    out.add(
        _bq_dataset_from_table(dig(d, "bigqueryConfig", "table")),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="BigQuery subscription",
    )
    bucket = dig(d, "cloudStorageConfig", "bucket")
    if bucket:
        out.add(
            f"//storage.googleapis.com/{bucket}",
            EdgeType.INVOKES,
            "STREAMS_TO",
            description="Cloud Storage subscription",
        )
    out.sa(
        dig(d, "bigqueryConfig", "serviceAccountEmail")
        or dig(d, "cloudStorageConfig", "serviceAccountEmail"),
        ctx,
        "export identity",
    )
    return bucket


def _delivery(endpoint: str | None, d: dict[str, Any], bucket: Any) -> str:
    if endpoint:
        return "push"
    if d.get("bigqueryConfig"):
        return "bigquery"
    return "cloud_storage" if bucket else "pull"


@_extractor("pubsub.googleapis.com/Subscription")
def _subscription(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(
        full_name(d.get("topic"), "pubsub"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        reverse=True,
        description="topic delivers to subscription",
    )
    push = d.get("pushConfig") or {}
    endpoint = url_alias(push.get("pushEndpoint"))
    if endpoint:
        out.add(endpoint, EdgeType.INVOKES, "INVOKES", description="push delivery")
    out.sa(dig(push, "oidcToken", "serviceAccountEmail"), ctx, "push authentication identity")
    out.add(
        full_name(dig(d, "deadLetterPolicy", "deadLetterTopic"), "pubsub"),
        EdgeType.INVOKES,
        "STREAMS_TO",
        description="dead-letter topic",
    )
    bucket = _subscription_exports(ctx, out)
    out.metadata.update(
        delivery=_delivery(endpoint, d, bucket),
        push_endpoint_host=endpoint,
        filter=d.get("filter"),
    )
