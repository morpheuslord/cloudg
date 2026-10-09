"""Constants, helpers and the shared identifier builders used by every
application / operations / integration collector mixin."""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable
from urllib.parse import urlparse

from cloudg.inventory.aws_services._base import (
    AWSServiceMixin,
    identifier_refs,
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.inventory.aws_services.containers import image_repository
from cloudg.schema.models import EdgeType

# One logger for the whole package, named as the original single module was.
logger = logging.getLogger(__name__.rpartition(".")[0])

_MAX_PARAMETERS = 10000
_MAX_LOG_GROUPS_FOR_FILTERS = 2000
_MAX_PROTECTED_RESOURCES = 5000

_ARN_ACCOUNT_RE = re.compile(r"^arn:aws[a-zA-Z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")
# Composite alarm rules reference child alarms as ALARM(name), OK(name) or
# INSUFFICIENT_DATA(name), optionally quoted. Parsed by a single left to right
# pass instead of a regular expression: every regex form of this backtracked
# on hostile rules ("OK(" followed by thousands of spaces, or "OK(" repeated).
_ALARM_STATES = ("INSUFFICIENT_DATA", "ALARM", "OK")


def _alarm_child_name(raw: str) -> str:
    name = raw.strip()
    if name.startswith('"'):
        name = name[1:]
    if name.endswith('"'):
        name = name[:-1]
    name = name.strip()
    return "" if '"' in name else name


def alarm_rule_children(rule: str) -> list[str]:
    """Child alarm names referenced by a composite alarm rule, in order."""
    out: list[str] = []
    i, n = 0, len(rule or "")
    while i < n:
        open_at = rule.find("(", i)
        if open_at < 0:
            break
        if not any(rule.endswith(state, 0, open_at) for state in _ALARM_STATES):
            i = open_at + 1
            continue
        j = open_at + 1
        while j < n and rule[j] not in "()":
            j += 1
        if j < n and rule[j] == ")":
            name = _alarm_child_name(rule[open_at + 1 : j])
            if name:
                out.append(name)
            j += 1
        i = j
    return out


_ASG_POLICY_RE = re.compile(r"autoScalingGroupName/([^:]+)")
_AWS_OWNED_DOC_PREFIXES = (
    "AWS-",
    "AWSEC2-",
    "AWSSupport-",
    "AWSConfigRemediation-",
    "Amazon",
    "AWSFIS-",
)


def _chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _arn_account(arn: Any) -> str | None:
    if not isinstance(arn, str):
        return None
    m = _ARN_ACCOUNT_RE.match(arn)
    return m.group(1) if m else None


def _host(url: Any) -> str | None:
    """Host part of an endpoint URL; paths, queries and credentials dropped."""
    if not isinstance(url, str) or not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname


def _clean_url(url: Any) -> str | None:
    """Repository URL without embedded credentials or query string."""
    if not isinstance(url, str) or not url:
        return None
    if "://" not in url:
        return url.split("?", 1)[0]
    p = urlparse(url)
    host = p.hostname or ""
    if p.port:
        host = f"{host}:{p.port}"
    return f"{p.scheme}://{host}{p.path}"


def _bucket_arn(location: Any) -> str | None:
    """S3 bucket ARN from 'bucket/prefix', 's3://bucket/...', or an S3 ARN."""
    if not isinstance(location, str) or not location:
        return None
    loc = location.strip()
    if loc.startswith("arn:aws:s3:::"):
        return "arn:aws:s3:::" + loc[len("arn:aws:s3:::") :].split("/", 1)[0]
    if loc.startswith("s3://"):
        loc = loc[5:]
    bucket = loc.split("/", 1)[0]
    return f"arn:aws:s3:::{bucket}" if bucket else None


def _ecr_repo(image: Any) -> str | None:
    """Repository reference for ECR images; None for public registries."""
    if not isinstance(image, str) or ".dkr.ecr." not in image:
        return None
    return image_repository(image)


def _is_aws_owned_document(name: str) -> bool:
    return name.startswith(_AWS_OWNED_DOC_PREFIXES)


def _env_names(variables: Any) -> list[str]:
    """Names from [{name|Name: ...}] or {name: value} env shapes."""
    if isinstance(variables, dict):
        return sorted(str(k) for k in variables)
    out = []
    for v in variables or []:
        if isinstance(v, dict):
            n = v.get("name", v.get("Name"))
            if n:
                out.append(str(n))
    return sorted(out)


def _env_values(variables: Any) -> dict[str, Any]:
    if isinstance(variables, dict):
        return variables
    out: dict[str, Any] = {}
    for v in variables or []:
        if isinstance(v, dict):
            out[str(v.get("name", v.get("Name", "")))] = v.get("value", v.get("Value"))
    return out


def _resource_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _vpc_config(source: dict, subnets_key: str, groups_key: str) -> dict[str, Any] | None:
    """The common ``vpc_config`` metadata shape, or None without a config."""
    if not source:
        return None
    return {
        "SubnetIds": source.get(subnets_key, []) or [],
        "SecurityGroupIds": source.get(groups_key, []) or [],
    }


def _efs_volume_relations(volumes: Any) -> list[dict | None]:
    """EFS file systems mounted through ECS-style ``volumes`` entries."""
    return [
        rel(
            (vol.get("efsVolumeConfiguration") or {}).get("fileSystemId"),
            EdgeType.REFERENCES,
            "READS_FROM",
            description=f"EFS volume {vol.get('name')}",
        )
        for vol in volumes or []
    ]


def _role_rel(role: Any, description: str) -> dict | None:
    """The workload-assumes-role relation most collectors declare."""
    return rel(role, EdgeType.ASSUMES_ROLE, "RUNS_ON", description=description)


class ApplicationBase(AWSServiceMixin):
    """Identifier builders shared by the application collector mixins."""

    def _cross_account(self, arn: Any) -> bool:
        acct = _arn_account(arn)
        return bool(acct and self._account_id and acct != self._account_id)

    def _app_iam_ref(self, value: Any, kind: str) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        if value.startswith("arn:"):
            return value
        name = value.lstrip("/") if kind == "role" else value
        return f"arn:aws:iam::{self._account_id}:{kind}/{name}"

    def _role_ref(self, value: Any) -> str | None:
        return self._app_iam_ref(value, "role")

    def _instance_profile_ref(self, value: Any) -> str | None:
        return self._app_iam_ref(value, "instance-profile")

    def _param_arn(self, name: str, region: str | None = None) -> str:
        if name.startswith("arn:"):
            return name
        return self._arn("ssm", "parameter/" + name.lstrip("/"), region)

    def _secret_or_param_ref(self, value: Any, kind: str = "auto") -> str | None:
        """Reference for a secret/parameter pointer (never its value).

        Secrets Manager ARNs may carry ``:json-key:stage:version`` suffixes;
        bare names are SSM parameter names (``kind='parameter'``) or secret
        names (``kind='secret'``).
        """
        if not isinstance(value, str) or not value:
            return None
        if value.startswith("arn:"):
            parts = value.split(":")
            if len(parts) > 7 and parts[2] == "secretsmanager":
                return ":".join(parts[:7])
            return value
        if kind == "secret":
            return value.split(":", 1)[0]
        return self._param_arn(value)

    def _log_group_arn(self, name: str, region: str | None = None) -> str:
        return self._arn("logs", f"log-group:{name}", region)

    def _env_relations(self, variables: Any, description: str) -> list[dict | None]:
        """Identifier-only references from plain environment values."""
        return [
            rel(ref, EdgeType.REFERENCES, "DEPENDS_ON", description=description)
            for ref in identifier_refs(_env_values(variables))
        ]

    def _app_secret_rel(self, value: Any, kind: str, description: str) -> dict | None:
        """READS_FROM a secret / parameter pointer (never its value)."""
        return rel(
            self._secret_or_param_ref(value, kind),
            EdgeType.REFERENCES,
            "READS_FROM",
            description=description,
        )

    def _app_statement_grants(
        self, st: dict, description: str | None
    ) -> tuple[list[dict | None], bool]:
        """GRANTS_ACCESS relations for one Allow statement's AWS principals,
        plus whether it allows ``*`` unconditionally."""
        relations: list[dict | None] = []
        public = False
        for p in policy_principals(st).get("AWS", []):
            if p == "*":
                public = public or not st.get("Condition")
                continue
            ref = principal_ref(p)
            relations.append(
                rel(
                    ref,
                    EdgeType.GRANTS_ACCESS,
                    "POLICY_ALLOWS_ACTION",
                    reverse=True,
                    description=description,
                    cross_account=self._cross_account(ref) or None,
                )
            )
        return relations, public

    def _app_policy_grants(self, doc: Any, description: str) -> tuple[list[dict | None], bool]:
        """Principal grants of every Allow statement in a resource policy."""
        relations: list[dict | None] = []
        public = False
        for st in policy_statements(doc):
            if st.get("Effect") != "Allow":
                continue
            st_rels, st_public = self._app_statement_grants(st, description)
            relations += st_rels
            public = public or st_public
        return relations, public
