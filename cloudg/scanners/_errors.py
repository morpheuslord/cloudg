"""How the scanner wrappers record failures, and raise them on request."""

from __future__ import annotations

import logging
from typing import ClassVar, Self

from cloudg.exceptions import (
    ReportParseError,
    ScannerError,
    ScannerFailed,
    ScannerNotInstalledError,
    ScannerOutputError,
    ScannerTimeoutError,
)

logger = logging.getLogger(__name__)


class ScannerErrorLog:
    """Failure bookkeeping shared by every scanner wrapper.

    ``errors`` lists, as text, why the last run did not finish (timeouts,
    launch failures). ``failures`` holds every :class:`ScannerError` the
    wrapper met, including output it could not parse, which does not stop a
    run and so is not in ``errors``. With ``strict`` set, the first failure
    is raised at once instead.
    """

    #: Short name used in messages and on the exceptions
    scanner_name: ClassVar[str] = "scanner"
    #: Executable looked up on PATH, and how to install it
    executable: ClassVar[str] = ""
    install_hint: ClassVar[str] = ""

    strict: bool = False
    #: Raised for unparseable output; parse_report switches it to ReportParseError
    _output_error: type[ScannerOutputError] = ScannerOutputError

    def _init_errors(self, strict: bool = False) -> None:
        self.strict = bool(strict)
        self.errors: list[str] = []
        self.failures: list[ScannerError] = []

    def _fail(self, exc: ScannerError, *, stops_run: bool = True) -> None:
        """Record ``exc``; raise it when ``strict``."""
        if not hasattr(self, "failures"):
            self._init_errors(self.strict)
        self.failures.append(exc)
        if stops_run:
            self.errors.append(exc.detail)
        if self.strict:
            raise exc

    def _timed_out(self, timeout_seconds: float, target: str | None = None) -> None:
        self._fail(ScannerTimeoutError(self.scanner_name, timeout_seconds, target=target))

    def _bad_output(self, detail: str, path: str | None = None) -> None:
        self._fail(self._output_error(self.scanner_name, detail, path=path), stops_run=False)

    @classmethod
    def _report_reader(cls, strict: bool, **kwargs: object) -> Self:
        """An instance for ``parse_report``: output problems become ReportParseError."""
        scanner = cls(strict=strict, **kwargs)  # type: ignore[call-arg]
        scanner._output_error = ReportParseError
        return scanner

    def _missing(self) -> None:
        """Called when the executable is not installed: a warning, or a raise when strict."""
        exc = ScannerNotInstalledError(self.scanner_name, self.executable, self.install_hint)
        if self.strict:
            raise exc
        logger.warning("%s. Skipping the %s scan.", exc, self.scanner_name)

    def raise_for_errors(self) -> None:
        """Raise when the last run recorded a failure; do nothing otherwise.

        A single failure is raised as it is (a :class:`ScannerTimeoutError`,
        :class:`ScannerOutputError`, ...). Several are raised together as a
        :class:`ScannerFailed` whose ``failures`` lists each one.
        """
        failures = list(getattr(self, "failures", None) or [])
        if not failures:
            return
        if len(failures) == 1:
            raise failures[0]
        raise ScannerFailed(self.scanner_name, [f.detail for f in failures], [], failures=failures)
