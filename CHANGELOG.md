# Changelog

Notable changes per release. Patch releases are folded into the major entry they belong to.

## 0.5.0 (unreleased)

Inventory mapping. A dedicated, scanner-independent function that maps everything deployed (or default) in a cloud estate and how it interlinks. It answers what exists and how it is wired together; the scanners keep answering what is wrong.

Added:

- `cloudg map` CLI command: deep-collects the complete infrastructure across AWS, Azure and GCP without running any scanner, links it into an interconnected map, and writes `inventory-map.json`, `inventory-map.graphml` and `inventory-graph.json`. `--findings` merges previously generated scanner findings into `asset-map.json` (asset → risk) and `compliance-map.json` (framework → affected assets).
- `cloudg.inventory` package, all public API:
  - `AWSDeepInventoryCollector` adds route tables, internet/NAT gateways, network interfaces, EBS volumes, Elastic IPs, NACLs, VPC peering, transit gateways and customer-managed IAM policies on top of the standard collector, plus a catch-all sweep of the Resource Groups Tagging API so every taggable resource appears on the map.
  - `AzureDeepInventoryCollector` adds NICs, public IPs, managed disks, load balancers and route tables, plus a full-subscription ARM `resources.list()` sweep covering every service.
  - `GCPDeepInventoryCollector` brings a richer Cloud Asset Inventory type taxonomy and IAM policy bindings as attachment edges.
  - `RelationshipLinker` derives interconnection edges purely from asset metadata (attachment, containment, routing, peering, and a generic cross-service reference pass) and works on any `list[CloudAsset]`.
  - `InventoryMapper` / `InventoryResult`: orchestration, summaries, exports, and the `build_asset_map()` / `build_compliance_map()` / `export_merged()` merge helpers.
- `CloudGEngine.map_inventory()` / `map_inventory_sync()` for embedders.
- `inventory:` config section (`tagging_sweep`, `link_references`).
- New schema values: `AssetType.NETWORK_INTERFACE`, `EdgeType.ATTACHED_TO`, `EdgeType.REFERENCES`.
- `MultiAccountCollector` accepts per-provider collector class overrides.
- Documentation: inventory mapping is covered in the README, the handbook (`cloudg map`, the inventory mapping API) and the docs site; a new "deeper toolkit" chapter documents the standalone programmatic APIs (GraphBuilder, CloudOntology, RAGExporter, TerraformExporter, FindingsNormaliser, parsers).

## 0.4.1 (2026-09-29)

Security hardening pass over the Checkov and Codacy findings.

- The Docker image now runs as a non-root `cloudg` user and carries a HEALTHCHECK.
- `install.sh` no longer pipes curl output straight into bash; installer scripts are downloaded to a temp file first (Homebrew, NodeSource, Azure CLI).
- Third-party GitHub Actions are pinned to full commit SHAs across all workflows.
- Plugin loading validates the `module:Class` path shape before `importlib.import_module`.
- Retry jitter uses the system RNG.
- Silent `except: pass` handlers now log at debug level, so swallowed errors are traceable.
- Log messages no longer put words like "credentials" next to runtime values.
- The vulnerability-report email moved out of SECURITY.md in favour of GitHub private reporting.
- A `.codacy.yml` scopes analysis to shipped code and documents suppressed false positives (pytest asserts, taxonomy names such as `AssetType.SECRET`).

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
