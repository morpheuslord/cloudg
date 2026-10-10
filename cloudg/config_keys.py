"""Unknown-key warnings for the configuration models in :mod:`cloudg.config`."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel

# Same logger as cloudg.config, where these warnings have always come from
logger = logging.getLogger("cloudg.config")


def _warn_unknown_keys(data: Any, model: type[BaseModel], path: str) -> None:
    """Log (not raise: CloudGConfig is public API) keys ``model`` does not define."""
    if not isinstance(data, dict):
        return
    for key in data:
        if key not in model.model_fields:
            logger.warning("Unknown config key %s is ignored", f"{path}.{key}" if path else key)


def _warn_unknown_keys_deep(data: Any, model: type[BaseModel], path: str) -> None:
    """:func:`_warn_unknown_keys` for ``model`` and every nested section model.

    Sections that check their own keys when validated (``ratelimit``) are
    left to their own validator so nothing is reported twice.
    """
    _warn_unknown_keys(data, model, path)
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        field = model.model_fields.get(key)
        sub = field.annotation if field is not None else None
        if (
            isinstance(sub, type)
            and issubclass(sub, BaseModel)
            and not getattr(sub, "_checks_own_keys", False)
        ):
            _warn_unknown_keys_deep(value, sub, f"{path}.{key}" if path else key)
