# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | yes |
| < 0.3 | no |

## Reporting a vulnerability

If you find a vulnerability in cloudg itself (credential handling, report
rendering, the way scanner output is parsed, anything else), please report it
privately:

* GitHub: use "Report a vulnerability" under the Security tab of this
  repository (private vulnerability reporting), or
* Email: the address listed for the maintainer on
  [PyPI](https://pypi.org/project/cloudg/)

Please include a description, steps to reproduce, and the version or commit
you tested. You can expect an acknowledgement within a few days. Please give
me a reasonable window to ship a fix before disclosing publicly.

## Scope notes

cloudg is a read-only auditing tool, but it handles sensitive material by
nature: cloud credentials, inventory data, and security findings. Reports and
findings files are written unencrypted to the output directory, so treat
`./reports` as sensitive. Issues about leaking credentials into logs, reports,
or exported files are firmly in scope and taken seriously.

Findings that cloudg reports about *your* cloud environment are not
vulnerabilities in cloudg. For false positives or missed checks, open a
regular bug report instead.
