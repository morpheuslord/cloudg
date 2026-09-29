# Changelog

Notable changes per release. Patch releases are folded into the major entry they belong to.

## 0.4.0 (2026-09-29)

Ingest mode. cloudg can now work entirely from scanner outputs you already have, with no cloud credentials and no scanner binaries on the machine.

Added:

- `cloudg ingest` CLI command. Takes `--prowler`, `--scoutsuite`, `--checkov` and `--trivy` paths (file or directory, each repeatable, any combination), runs the normaliser and the check-equivalence merge over them, and renders the HTML and JSON reports.
- `parse_report(path)` classmethods on `ProwlerScanner`, `ScoutSuiteScanner`, `CheckovScanner` and `TrivyScanner`. Each parses the tool's native output format directly. Trivy image and filesystem reports are told apart by the `ArtifactType` field.
- `cloudg.ingest` module with `parse_report(tool, path)` and `ingest_reports(mapping)`.
- `CloudGEngine.ingest_reports()`, `CloudGEngine.normalise_findings()` and `CloudGEngine.run_from_reports()` / `run_from_reports_sync()` for embedders.
- Feature documentation: `docs/DOCUMENTATION.md`, a rendered handbook at `docs/index.html`, and this changelog.

Fixed:

- The publish workflow now sets an explicit least-privilege `permissions` block (CodeQL `actions/missing-workflow-permissions`).

## 0.3.0 (2026-09-26)

The rebrand release: the project, package, CLI, Docker image, installers and CI became cloudg (cloud graphing).

- Renamed everything to cloudg; classes follow as `CloudGConfig` and `CloudGEngine`.
- Multi-cloud authentication: OIDC web identity federation, STS role assumption with external IDs and multi-account fan-out on AWS; workload identity federation, service principals, managed identity on Azure; credential files and service account impersonation on GCP.
- Expanded compliance rulesets, generated from Prowler's public compliance data: 28 frameworks, 4,166 controls, 10,236 check mappings across AWS, Azure and GCP.
- uv-based packaging and a PyPI publish workflow using trusted publishing (OIDC), plus a Docker image on GHCR bundling all four scanner binaries.
- MIT license and community standards files.

Patch releases folded in:

- 0.3.1 (2026-09-26): the IaC scanners no longer fall back to silently scanning the current working directory; they target configured directories or the Terraform recreation of the live infrastructure, and are skipped otherwise.
- 0.3.2 (2026-09-28): finding deduplication is keyed on scanner check IDs with the `rules/check_equivalence.yaml` cross-scanner map, instead of resource and title alone. The CLI moved to a dedicated Rich UI layer.

## Before 0.3.0

The pre-rebrand history (April 2026): the async AWS collector grew ECS, DynamoDB, CloudFront, Secrets Manager and KMS support with adaptive retries; scanners moved to parallel execution under a thread pool; the Terraform export renderer and live-streaming Prowler output landed; the Click CLI took shape.
