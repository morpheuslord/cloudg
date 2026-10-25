"""Run Checkov through cloudg and stop at the first problem."""

from cloudg.exceptions import ScannerError, ScannerNotInstalledError, ScannerTimeoutError
from cloudg.scanners.checkov import CheckovScanner

scanner = CheckovScanner(target_dir="infra/", timeout_seconds=600, strict=True)

try:
    findings = scanner.run()
except ScannerNotInstalledError as exc:
    print(f"{exc.executable} is missing. {exc.install_hint}")
except ScannerTimeoutError as exc:
    print(f"gave up on {exc.target} after {exc.timeout_seconds:g}s")
except ScannerError as exc:  # launch failures, unreadable output
    print(f"{exc.scanner} failed: {exc.detail}")
else:
    print(len(findings), "findings")
