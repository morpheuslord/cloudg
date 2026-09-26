# Contributing to cloudg

Thanks for taking an interest in the project. Bug reports, fixes, new
collectors and scanner integrations are all welcome.

## Setting up

The project uses uv. Python 3.11 or newer is required.

```bash
git clone https://github.com/morpheuslord/cloudg.git
cd cloudg
uv venv && source .venv/bin/activate
uv pip install -e ".[all,dev]"
```

The external scanners (Prowler, Checkov, Trivy, ScoutSuite) are optional for
development. The test suite mocks AWS with moto, so you can work on almost
everything without cloud credentials.

## Before you open a PR

Run the same checks CI runs:

```bash
pytest
ruff check cloudg/ tests/ scripts/
ruff format --check cloudg/ tests/
```

A few things that make review easier:

* Keep PRs focused. A rename and a feature in one PR is hard to review.
* Add or update tests for behavior you change. The suite currently sits at
  152 tests and should not go red.
* New collectors and scanners register through entry points (see
  `pyproject.toml`), not by editing the pipeline core.
* Match the style around you. The codebase logs failures and keeps going
  rather than crashing the pipeline; error handling should follow that
  pattern.

## Rulesets and policies

Compliance rulesets live in `cloudg/rules/`. The files under
`cloudg/rules/frameworks/` are generated from Prowler's public compliance
data. Do not edit those by hand; refresh them instead:

```bash
git clone --depth 1 https://github.com/prowler-cloud/prowler /tmp/prowler
python scripts/import_prowler_compliance.py /tmp/prowler
```

Hand-written rulesets (regex pattern files) can be edited directly, and new
frameworks are welcome as long as they reference a public standard.

## Reporting bugs

Use the bug report issue template. Logs from a `-v` (verbose) run and your
provider/region setup help a lot. Never paste credentials, account IDs you
care about, or raw findings from a real environment into an issue.

## Security issues

Do not open a public issue for anything security-sensitive. See
[SECURITY.md](SECURITY.md).
