"""CI/CD: Cloud Build private worker pools, repository connections (Cloud
Build 2nd gen and Developer Connect) and the source / pool a build trigger
uses."""

from __future__ import annotations

from typing import Any, Iterator

from cloudg.inventory.gcp_relations._refs import parent_of, secret_version_ref
from cloudg.inventory.gcp_relations.context import Extracted, GCPContext, _extractor
from cloudg.inventory.gcp_relations.names import _list, dig, full_name, url_alias
from cloudg.schema.models import EdgeType


def _secret_versions(value: Any, depth: int = 0) -> Iterator[str]:
    """Every ``...SecretVersion`` value in a connection config."""
    if depth > 5:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, str) and (k.endswith("SecretVersion") or k.endswith("secretVersion")):
                yield v
            else:
                yield from _secret_versions(v, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _secret_versions(item, depth + 1)


def _connection_secrets(out: Extracted, d: dict[str, Any]) -> None:
    for version in dict.fromkeys(_secret_versions(d)):
        out.add(
            secret_version_ref(version),
            EdgeType.REFERENCES,
            "READS_FROM",
            description="repository credentials",
        )


def _provider(d: dict[str, Any]) -> str | None:
    return next(
        (k.removesuffix("Config") for k in d if k.endswith("Config") and isinstance(d[k], dict)),
        None,
    )


@_extractor("cloudbuild.googleapis.com/WorkerPool")
def _worker_pool(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    cfg = d.get("privatePoolV1Config") or {}
    net = cfg.get("networkConfig") or {}
    out.add(full_name(net.get("peeredNetwork"), "compute"), EdgeType.PEERING, "VPC_PEERED")
    out.add(
        full_name(dig(cfg, "privateServiceConnect", "networkAttachment"), "compute"),
        EdgeType.ATTACHED_TO,
    )
    out.metadata.update(
        egress=net.get("egressOption"),
        machine_type=dig(cfg, "workerConfig", "machineType"),
        public_egress=net.get("egressOption") != "NO_PUBLIC_EGRESS",
    )


@_extractor(
    "cloudbuild.googleapis.com/Connection",
    "developerconnect.googleapis.com/Connection",
    "cloudbuild.googleapis.com/GithubEnterpriseConfig",
    "cloudbuild.googleapis.com/BitbucketServerConfig",
)
def _repo_connection(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    _connection_secrets(out, d)
    out.add(full_name(d.get("peeredNetwork"), "compute"), EdgeType.PEERING, "VPC_PEERED")
    host = (
        d.get("hostUri")
        or dig(d, "githubEnterpriseConfig", "hostUri")
        or dig(d, "gitlabConfig", "hostUri")
        or dig(d, "gitlabEnterpriseConfig", "hostUri")
        or dig(d, "bitbucketDataCenterConfig", "hostUri")
    )
    out.metadata.update(
        provider=_provider(d),
        host=url_alias(host),
        installation_state=dig(d, "installationState", "stage"),
        disabled=d.get("disabled"),
    )


@_extractor(
    "cloudbuild.googleapis.com/Repository", "developerconnect.googleapis.com/GitRepositoryLink"
)
def _repo_link(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    parent = parent_of(ctx.name, "repositories") or parent_of(ctx.name, "gitRepositoryLinks")
    out.add(parent, EdgeType.CONTAINS, reverse=True)
    uri = d.get("remoteUri") or d.get("cloneUri")
    out.metadata["remote_uri"] = uri


@_extractor("developerconnect.googleapis.com/InsightsConfig")
def _insights_config(ctx: GCPContext, out: Extracted) -> None:
    d = ctx.data
    out.add(full_name(d.get("appHubApplication"), "apphub"), EdgeType.MONITORS, "MONITORED_BY")
    for ref in _list(d.get("artifactConfigs")):
        uri = ref.get("uri") if isinstance(ref, dict) else None
        out.add(
            full_name(uri, "artifactregistry") if uri else None, EdgeType.MONITORS, "MONITORED_BY"
        )


@_extractor("cloudbuild.googleapis.com/BuildTrigger")
def _build_trigger_sources(ctx: GCPContext, out: Extracted) -> None:
    """2nd gen repository, Developer Connect link and private pool of a trigger."""
    d = ctx.data
    out.add(
        full_name(dig(d, "repositoryEventConfig", "repository"), "cloudbuild"),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="source repository",
    )
    out.add(
        full_name(dig(d, "developerConnectEventConfig", "gitRepositoryLink"), "developerconnect"),
        EdgeType.REFERENCES,
        "READS_FROM",
        description="source repository link",
    )
    out.add(
        full_name(dig(d, "sourceToBuild", "repository"), "cloudbuild"),
        EdgeType.REFERENCES,
        "READS_FROM",
    )
    out.add(
        full_name(dig(d, "build", "options", "pool", "name"), "cloudbuild"),
        EdgeType.REFERENCES,
        "RUNS_ON",
        description="private worker pool",
    )
