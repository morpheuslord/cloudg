"""Scan several images, keep every result, then decide what counts as failure."""

from cloudg.exceptions import ScannerError, ScannerFailed
from cloudg.scanners.trivy import TrivyScanner

scanner = TrivyScanner(timeout_seconds=900)
findings = scanner.scan_images(["nginx:1.27", "python:3.12-slim"])

print(len(findings), "findings,", len(scanner.failures), "failures recorded")
for failure in scanner.failures:
    print(" -", type(failure).__name__, failure.detail)

try:
    scanner.raise_for_errors()
except ScannerFailed as exc:  # more than one failure: all of them, in order
    for failure in exc.failures:
        print("failed:", failure)
except ScannerError as exc:  # exactly one failure, raised as it is
    print("failed:", exc)
