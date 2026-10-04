"""Constants and helpers shared by the security service collectors."""

from __future__ import annotations

import logging
from typing import Any

from cloudg.inventory.aws_services._base import AWSServiceMixin, error_code, rel
from cloudg.schema.models import EdgeType

logger = logging.getLogger(__package__)  # the package logger, as before the split

_NOT_ENABLED_CODES = {
    "InvalidAccessException",
    "ResourceNotFoundException",
    "AccessDeniedException",
    "BadRequestException",
    "NoSuchConfigurationRecorderException",
}


def _not_enabled(exc: BaseException) -> bool:
    """The service is not deployed here (or its API is closed to us)."""
    return error_code(exc) in _NOT_ENABLED_CODES


def _disabled_reason(exc: BaseException) -> str:
    return (
        "not enabled or access denied"
        if error_code(exc) == "AccessDeniedException"
        else "not enabled"
    )


def _administrator_rel(admin: str | None, description: str) -> dict[str, Any] | None:
    """The delegated administrator account that watches this deployment."""
    return rel(
        f"arn:aws:iam::{admin}:root" if admin else None,
        EdgeType.MONITORS,
        "MONITORED_BY",
        reverse=True,
        description=description,
    )


class SecurityServiceMixin(AWSServiceMixin):
    """Helpers shared by every security collector."""

    _is_primary_region: bool = True

    def _monitors_account(self, description: str, **properties: Any) -> dict[str, Any] | None:
        """The service watches this account."""
        return rel(
            self._account_ref(),
            EdgeType.MONITORS,
            "MONITORED_BY",
            description=description,
            **properties,
        )

    async def _security_listing(
        self, client: Any, operation: str, key: str, failure: str
    ) -> list[Any]:
        """An optional listing; on failure keep what was read and log ``failure``."""
        items: list[Any] = []
        try:
            async for item in self._paginate(client, operation, key):
                items.append(item)
        except Exception as exc:
            logger.debug(failure, exc)
        return items
