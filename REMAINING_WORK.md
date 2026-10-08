# Remaining work on feature-mcp-layer (PR #26)

Snapshot of 2026-10-08. The branch is synced with origin/main at 368efce and carries the
undelivered fix/parallel-rule-edges commit. Delete this file before the PR merges.

## Where things stand

- The last commit is a work-in-progress checkpoint. Five fix groups were stopped partway through
  their work, and their uncommitted edits were committed as they were.
- `ruff check cloudg tests` passes. `ruff format --check` fails on 56 files (the new MCP and
  resilience code); CI's lint job fails until `ruff format cloudg tests` is run.
- Tests outside `tests/mcp`: 702 passed.
- `tests/mcp`: 815 passed, 16 failed, 6 skipped. The failures are tests that still assert the old
  "did you mean" error text, which G2 had started moving into error `data`, and the half-split
  `state` package:
  - test_catalog_export_live_meta.py::test_terraform_preview
  - test_catalog_findings.py::test_list_findings_projection_pagination_errors, test_findings_for_asset
  - test_catalog_graph.py::test_neighbors_errors, test_find_paths
  - test_catalog_inventory.py::test_find_assets_bad_filters, test_get_asset_not_found_suggests
  - test_catalog_ontology.py::test_ontology_neighbourhood
  - test_catalog_prompts.py::test_prompt_errors
  - test_catalog_regressions.py::test_snapshot_refuses_existing_name
  - test_catalog_resources.py::test_asset_templates
  - test_catalog_workspace.py::test_select_unknown, test_snapshot_and_diff_tools, test_dataset_summary
  - test_state.py::test_resolve_asset_suggests_close_matches, test_workspace_load_select_remove_and_events
- Codacy on PR #26 reports 99 new issues (2 critical, 14 high, 83 medium, mostly complexity) and
  24 duplicated blocks. CodeQL reports two ReDoS alerts.

## Already done and pushed

- Repaired main's merge leftovers: the pasted-together `tests/test_reachability.py` (now
  `tests/test_ports.py` plus `tests/test_reachability.py`, 41 tests running again) and the
  duplicate import in `cloudg/graph/reachability.py`.
- Delivered fix/parallel-rule-edges, which was never pushed: GraphBuilder merges parallel rule
  edges, so SSH open to the world is reported again.
- Strict-profile leak fixes (org ids, dependency ids, ontology IRIs, RAG text, account keys).
- Pre-existing Codacy issues from main: duplicate CloudGConfig import, mixin stub
  "assignment from no return", unpinned parliament in the Dockerfile.
- CI actions moved to their Node 24 releases; the uv cache now keys on pyproject.toml.
- Each parallel session's goal was checked against the merged code: all six fix sessions
  delivered; nothing was overwritten.

## Groups needed: 7

Five code groups and two documentation groups. Each group owns its files outright, so they can
run in parallel without touching each other's work. The lead commits and pushes each group as it
finishes.

### G1. Graph core

Files: cloudg/graph/{reachability,ports,builder,ontology,ontology_rules,rag_export}.py,
cloudg/inventory/dependencies.py, tests/test_{ports,reachability,graph_builder,ontology,
rag_export,normaliser}.py. Status: partly done, uncommitted work included in the checkpoint.

- Finding ids are not stable across scans: they hash the random per-collection asset uuid. Hash
  the ARN (or id) instead, for both exposure and open-port findings.
- Three different "is this the internet" checks disagree; Azure NSG sources `Internet`, `*` and
  `Any` produce exposure findings but no open-port findings. One shared helper everywhere.
- Duplicated port and rule-edge constants across ports.py, reachability.py, builder.py and
  ontology_rules.py (the ontology still uses the old `ports` list and `"0-65535"` string test).
- Public network-flow API (flow successors / flow graph) for the MCP layer to reuse.
- AssetIndex as the single asset matcher: ARN-tail tiers, optional case-insensitive names, a
  finding resolver; the KMS key matcher scans every asset per encrypted asset (index it once).
- Containment relations check only the source type; check the target too.
- Target groups are reported as "unexpected internet-exposed resources".
- RAG lost ENCRYPTED_BY_KMS and VPC containment entirely.
- Relation count in docstrings (64).
- Test cleanups: private-method tests, a test of an impossible path, a duplicated normaliser
  test, and missing interaction tests (multi-rule SG end to end, Azure Internet sources, id
  stability, ontology triples for SG edges).
- Codacy complexity on these files.

### G2. MCP catalog and workspace

Files: cloudg/mcp/state.py (being split into the cloudg/mcp/state/ package), cloudg/mcp/catalog/*
except privacy.py, tests/mcp/{conftest.py,fixtures/*,test_state.py,test_catalog_*.py}.
Status: partly done; the state package split and error-message changes are half applied (the 16
failing tests).

- Codacy: every catalog `register()` is too complex because handlers are nested inside it; move
  handlers to module level. Long and parameter-heavy functions (find_assets, organization_topology,
  filter_assets, count_assets, get_edges, ingest_reports, diff_datasets). Files over 500 lines
  (state.py, graph.py, inventory.py). `format` argument shadows a builtin (keep the wire name).
  Unsafe yaml.load. B105 false positive. Duplicate depends_on/dependents bodies.
- CodeQL: the SPARQL UPDATE detection regex can backtrack exponentially; replace with a scanner.
- flow_graph reports false internet paths; use G1's network-flow API.
- Finding-to-asset matching disagrees with AssetIndex; use it.
- graph.py has its own port and internet parsing (misses Azure `*`, GCP all-ports, ICMP, egress).
- Security: allowed roots default to the working directory (can be `/`); load errors echo file
  contents; unbounded rglob.
- Security (strict profile): "did you mean" suggestions and handler errors echo real names;
  resources and prompts return pre-serialised text that skips key-based redaction (prompt data
  goes through the agreed `cloudg/data` + `cloudg/render` meta marker); textual graph and
  ontology exports, subgraph_export and sparql_query become RESTRICTED.
- Lock nesting lets one slow ontology build stall every dataset.
- reachability_findings overrides main's deterministic ids; cursors survive dataset replacement;
  trivy image arguments starting with `-`; SPARQL has no cost limit.
- explain_edge_type relation text is stale; blast_radius output order is random.

### G3. MCP privacy

Files: cloudg/mcp/policy.py, cloudg/mcp/transforms/*, cloudg/mcp/policies/*.yaml,
cloudg/mcp/catalog/privacy.py, tests/mcp/{test_transforms,test_policy,test_policy_regressions,
test_privacy_tools}.py. Status: partly done.

- CodeQL/semgrep critical: vault `_SHAPE_RE` can backtrack exponentially; check the other
  transform regexes too.
- Codacy: B105 false positives on label strings, an `assert`, a silent try/except, and complexity
  or length in policy.py, detectors.py, redaction.py, vault.py, projection.py, annotation.py and
  privacy.py; duplicated branches in projection._walk.
- Security: record restored (real, token) pairs so every outgoing string of a call can be
  re-pseudonymised (errors were a reveal oracle); redact pre-serialised text using the vault's
  known values; let deny/allow rules match the concrete resource URI; preview_transform must not
  confirm pseudonym guesses; privacy_audit_log needs an admin gate; escape CR/LF in audit lines.
- Performance: strict mode on 50k assets takes about 21 s cold.

### G4. MCP core, layer and servers

Files: cloudg/mcp/{__init__,__main__,core,layer,schema,context,middleware,server,cli}.py,
cloudg/mcp/adapters/*, cloudg/mcp/native/*, the mcp lines of cloudg/cli.py,
tests/mcp/{_adapter_testkit.py,test_adapters_*,test_native_*,test_middleware,test_cli_mcp}.py.
Status: barely started (new content.py and layer_output.py modules from the core and layer split).

- Codacy critical: `importlib.import_module` on the `--registry` value; validate it.
- Codacy: an `assert`, silent try/except blocks, many long or parameter-heavy functions
  (server.py serve paths, cli.py serve_cmd, native http/protocol/stdio, fastmcp adapter), files
  over 500 lines (core.py, layer.py, native/http.py, native/protocol.py).
- Duplication: protocol tools/call vs prompts/get, http GET vs DELETE and body parsing, adapter
  notify and principal extraction, change dispatch, fastmcp run_tool vs render, Registry
  resource vs resource_template.
- Security: transform errors from resources, prompts and completions; never forward raw handler
  exception text; re-pseudonymise restored values; apply the `cloudg/data` marker; transform
  link titles and embedded resource URIs; send progress and log messages through the policy;
  DNS rebinding on non-loopback binds; an empty `--auth-token` must fail; canonicalise resource
  URIs before policy checks; per-principal session caps, a connection cap and header timeout;
  session binding on the SDK and fastmcp flavors.

### G5. Resilience and older main issues

Files: cloudg/resilience/*, cloudg/retry.py, cloudg/config.py (rate-limit parts),
cloudg/collectors/{gcp,azure,multi}.py, cloudg/credentials.py, cloudg/inventory/{linker,mapper,
mapper_result,gcp_deep}.py, cloudg/inventory/azure_graph/query.py, cloudg/api.py,
cloudg/renderers/svg_layout.py, cloudg/cli_run_helpers.py, cloudg/cli_commands.py,
tests/{test_resilience,conftest,test_api,test_collectors}.py, tests/test_inventory*.py.
Status: partly done (new linker_rules.py, resilience refactors).

- High: a half-open circuit breaker can stay stuck forever after a fatal error, cancellation or
  deadline (process-wide, every call in that service scope rejected). Timestamp the probe and
  treat a fatal provider answer as a health signal.
- High: a tripped GCP Cloud Asset Inventory breaker never recovers on multi-page listings (page 2
  of the probe is rejected by its own breaker). Rate-limit only in `paced()`; never count calls
  that were rejected before sending as failures (same bug in the Azure collector).
- `with_retry` now retries far more than before (any HTTP 500, text matches, its own circuit and
  budget errors); restrict it.
- Instrumented boto3 sessions raise errors that are not botocore exceptions (breaks
  `except ClientError` in embedders).
- A hung live operation pins its scope as busy forever; add a timeout.
- The process-wide retry budget gates botocore's own retries for the life of the process.
- Governor reconfiguration cross-talk between concurrent runs; bulkhead slots on cancelled
  aioboto3 calls; sync hooks sleeping on the event loop; nested Resource Graph retries.
- mapper.deduplicate collapses parallel security group rule edges whenever an asset was merged.
- Codacy: silent try/except blocks, Azure policy class complexity 33, functions with 10
  parameters (guard, call_with_resilience), duplicated needs_retry, an unused re-export in
  cloudg/retry.py, one issue in collectors/gcp.py, and main's older findings
  (linker._link_rules complexity 28, api.py 612 lines, svg_layout and cli_run_helpers parameter
  counts).

### D1. Documentation refresh (after G1 to G5 land)

docs/MCP.md, MCP_TOOLS.md, MCP_PRIVACY.md, MCP_INTERNALS.md, RESILIENCE.md, DOCUMENTATION.md,
INVENTORY_REFERENCE.md, INVENTORY_CATALOG.md, INVENTORY_INTERNALS.md, docs/index.html, README.md.

- Regenerate every MCP_TOOLS.md example from the final code (the reachability, ontology and RAG
  examples went stale with main's fixes) and fix the prose that describes the old behaviour.
- PyPI page: eight relative links that 404 on PyPI; reachability, relation count, Finding.id and
  is_internet_exposed wording.
- Inventory docs: graph exports are no longer one-to-one with edges, port and protocol formats per
  provider, the throttling field, AWS CONTAINS edges, GCP internet edges, 0.5.x references.
- MCP_PRIVACY.md and RESILIENCE.md: fixed known gaps, new detectors and key rules, UUID ids kept
  under strict, small resilience inaccuracies, plus whatever G3 and G5 change.
- Handbook changelog entry for main's merged fixes.

### D2. CHANGELOG rewrite and dash sweep (lead, last)

- Rewrite the 0.6.0 CHANGELOG entry as one coherent release note: it is currently three entries
  stuck together with a stray `=======` marker that renders a paragraph as a heading, and it says
  "all public API changes are additive" while listing behaviour changes.
- Remove the 140 remaining em dashes in older code, help text, CLI output and rule files.
- Run `ruff format cloudg tests` and the full CI-equivalent check, then push.
