"""Principal grants read from a resource policy (S3 bucket, ECR repository)."""

from __future__ import annotations

from typing import Any

from cloudg.inventory.aws_services._base import (
    policy_principals,
    policy_statements,
    principal_ref,
    rel,
)
from cloudg.schema.models import EdgeType


def principal_grants(
    policy: Any, description: str, *, conditioned_public: bool
) -> tuple[list[dict | None], bool]:
    """READS_FROM grants for every AWS principal the policy allows, plus
    whether it allows anyone (``"*"``).

    Args:
        policy: The policy document (JSON string or dict).
        description: Edge description, e.g. "bucket policy grant".
        conditioned_public: Whether a ``"*"`` grant counts as public even
            when the statement carries a Condition.
    """
    allowed = [st for st in policy_statements(policy) if st.get("Effect") == "Allow"]
    relations: list[dict | None] = []
    public = False
    for st in allowed:
        principals = policy_principals(st).get("AWS", [])
        if "*" in principals:
            public = public or conditioned_public or not st.get("Condition")
        relations += [
            rel(
                principal_ref(p),
                EdgeType.GRANTS_ACCESS,
                "READS_FROM",
                reverse=True,
                description=description,
            )
            for p in principals
            if p != "*"
        ]
    return relations, public
