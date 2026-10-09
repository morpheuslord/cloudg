"""Vault construction and save-at-exit for policies (see
:mod:`cloudg.mcp.policy`)."""

from __future__ import annotations

import atexit
import logging
import weakref

from cloudg.mcp.policy.config import VaultConfig
from cloudg.mcp.transforms import TokenVault

logger = logging.getLogger("cloudg.mcp")


def vault_from_config(vc: VaultConfig) -> TokenVault:
    return TokenVault(
        key=vc.key.get_secret_value() if vc.key else None,
        scope=vc.scope,
        ttl_seconds=vc.ttl_seconds,
        path=vc.path,
        autosave=vc.autosave,
        encrypt=vc.encrypt,
        key_env=vc.key_env,
    )


_EXIT_VAULTS: "weakref.WeakSet[TokenVault]" = weakref.WeakSet()
_EXIT_HOOKED = False


def _register_exit_save(vault: TokenVault) -> None:
    """Save vaults that have a path at interpreter exit (if they changed).
    Weak references: a vault that was garbage collected is skipped."""
    global _EXIT_HOOKED
    _EXIT_VAULTS.add(vault)
    if not _EXIT_HOOKED:
        atexit.register(_save_vaults_at_exit)
        _EXIT_HOOKED = True


def _save_vaults_at_exit() -> None:
    for vault in list(_EXIT_VAULTS):
        try:
            if vault.path is not None and vault.dirty:
                vault.save()
        except Exception:  # never fail interpreter shutdown
            logger.debug("vault save at exit failed", exc_info=True)
