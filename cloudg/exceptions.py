"""Every exception cloudg raises on purpose, in one importable place.

All of them derive from :class:`CloudGError`, so one ``except CloudGError``
catches anything cloudg itself raised, while SDK and OS errors keep passing
through untouched. The narrower classes also keep the built-in base they
always had (``ValueError``, ``RuntimeError``, ``ImportError``), so existing
``except ValueError`` code goes on working.

::

    CloudGError
    ├── ConfigurationError            (ValueError)
    ├── ProviderSDKMissingError       (ImportError)
    ├── CollectionError               (RuntimeError)
    │   ├── CredentialError
    │   └── OrganizationScopeError    (ValueError)
    ├── ScannerError
    │   ├── ScannerNotInstalledError
    │   ├── ScannerTimeoutError
    │   ├── ScannerExecutionError
    │   ├── ScannerOutputError
    │   │   └── ReportParseError
    │   └── ScannerFailed             (RuntimeError)
    ├── ResilienceError               (cloudg.resilience)
    └── LiveOperationRejected         (cloudg.resilience)

Scanner wrappers record failures instead of raising, so one broken scanner
never stops a pipeline. To get exceptions instead, pass ``strict=True`` to
the wrapper, or call :meth:`raise_for_errors` after a run::

    from cloudg.exceptions import ScannerError, ScannerTimeoutError
    from cloudg.scanners.checkov import CheckovScanner

    scanner = CheckovScanner(target_dir="infra/", timeout_seconds=600)
    findings = scanner.run()
    try:
        scanner.raise_for_errors()
    except ScannerTimeoutError as exc:
        print(f"{exc.scanner} gave up after {exc.timeout_seconds}s")
    except ScannerError as exc:
        print(f"{exc.scanner} failed: {exc.detail}")

This module imports nothing from the rest of cloudg, so any module can
import it without a cycle.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "CloudGError",
    "CollectionError",
    "ConfigurationError",
    "CredentialError",
    "OrganizationScopeError",
    "ProviderSDKMissingError",
    "ReportParseError",
    "ScannerError",
    "ScannerExecutionError",
    "ScannerFailed",
    "ScannerNotInstalledError",
    "ScannerOutputError",
    "ScannerTimeoutError",
]


class CloudGError(Exception):
    """Base of every exception cloudg raises on purpose."""


class ConfigurationError(CloudGError, ValueError):
    """A configuration value is missing, malformed or contradicts another."""


class ProviderSDKMissingError(CloudGError, ImportError):
    """A provider's SDK is not installed.

    ``provider`` is ``"aws"``, ``"azure"`` or ``"gcp"`` and ``extra`` the pip
    extra that installs it, so the message can say ``pip install cloudg[gcp]``.
    """

    def __init__(self, provider: str, extra: str | None = None, missing: str | None = None) -> None:
        self.provider = provider
        self.extra = extra or provider
        self.missing = missing
        what = f" ({missing})" if missing else ""
        super().__init__(
            f"the {provider} SDK is not installed{what}; run: pip install 'cloudg[{self.extra}]'"
        )


class CollectionError(CloudGError, RuntimeError):
    """Collecting inventory from a cloud provider failed."""


class CredentialError(CollectionError):
    """No usable credentials were found for a provider, or they were refused."""

    def __init__(self, provider: str, detail: str) -> None:
        self.provider = provider
        self.detail = detail
        super().__init__(f"{provider}: {detail}")


class OrganizationScopeError(CollectionError, ValueError):
    """The requested organization scope (an OU filter) names nothing in the org.

    Raised instead of quietly mapping only the caller's account.
    """


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------


class ScannerError(CloudGError):
    """A security scanner could not produce a complete result.

    ``scanner`` is the wrapper's short name (``"prowler"``, ``"checkov"``,
    ...), ``detail`` the reason in a few words and ``target`` what was being
    scanned (an image, a directory, a report file), when there is one.
    """

    def __init__(self, scanner: str, detail: str, *, target: str | None = None) -> None:
        self.scanner = scanner
        self.detail = detail
        self.target = target
        super().__init__(f"{scanner}: {detail}")


class ScannerNotInstalledError(ScannerError):
    """The scanner's executable is not on ``PATH``."""

    def __init__(self, scanner: str, executable: str, install_hint: str = "") -> None:
        self.executable = executable
        self.install_hint = install_hint
        detail = f"{executable!r} is not on PATH"
        if install_hint:
            detail += f"; install with: {install_hint}"
        super().__init__(scanner, detail)


class ScannerTimeoutError(ScannerError):
    """The scanner ran longer than its ``timeout_seconds`` and was killed."""

    def __init__(self, scanner: str, timeout_seconds: float, *, target: str | None = None) -> None:
        self.timeout_seconds = timeout_seconds
        detail = f"timed out after {timeout_seconds:g}s"
        if target:
            detail += f" scanning {target}"
        super().__init__(scanner, detail, target=target)


class ScannerExecutionError(ScannerError):
    """The scanner process could not be started, or crashed.

    ``returncode`` is the exit status when the process ran; ``output`` the
    tail of what it printed, when that was captured.
    """

    def __init__(
        self,
        scanner: str,
        detail: str,
        *,
        target: str | None = None,
        returncode: int | None = None,
        output: str = "",
    ) -> None:
        self.returncode = returncode
        self.output = output
        super().__init__(scanner, detail, target=target)


class ScannerOutputError(ScannerError):
    """The scanner ran, but its output could not be read or parsed."""

    def __init__(
        self, scanner: str, detail: str, *, target: str | None = None, path: str | None = None
    ) -> None:
        self.path = path
        super().__init__(scanner, detail, target=target or path)


class ReportParseError(ScannerOutputError):
    """An existing report handed to ``parse_report`` or ``cloudg ingest`` is unreadable."""


class ScannerFailed(ScannerError, RuntimeError):
    """A scanner started but did not finish (timeout, launch failure).

    ``findings`` holds whatever it produced before that (for example the
    images Trivy did scan), so callers can keep partial results. ``errors``
    are the recorded reasons as text and ``failures`` the matching
    :class:`ScannerError` objects, when the wrapper recorded them.
    """

    def __init__(
        self,
        scanner: str,
        errors: list[str],
        findings: list[Any],
        failures: list[ScannerError] | None = None,
    ) -> None:
        self.errors = list(errors)
        self.findings = findings
        self.failures = list(failures or [])
        ScannerError.__init__(self, scanner, "; ".join(self.errors))
        # Keep the message format callers already match on: "<scanner> <reasons>"
        self.args = (f"{scanner} " + "; ".join(self.errors),)
