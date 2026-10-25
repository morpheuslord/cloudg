"""Fail an ingest job when a report file is truncated or not a report at all."""

import sys

from cloudg.exceptions import ReportParseError
from cloudg.scanners.checkov import CheckovScanner

path = sys.argv[1] if len(sys.argv) > 1 else "results_json.json"

try:
    findings = CheckovScanner.parse_report(path, strict=True)
except ReportParseError as exc:
    sys.exit(f"{exc.scanner} report {exc.path} is unreadable: {exc.detail}")

print(len(findings), "findings in", path)
