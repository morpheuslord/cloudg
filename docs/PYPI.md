<p align="center">
  <img src="https://raw.githubusercontent.com/morpheuslord/cloudg/main/assets/cloudg_animated_logo.gif" width="480" alt="cloudg logo">
</p>

<h1 align="center">cloudg</h1>

<p align="center"><strong>Map the cloud. Scan it. Merge everything.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/cloudg/"><img src="https://img.shields.io/pypi/v/cloudg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/cloudg/"><img src="https://img.shields.io/pypi/pyversions/cloudg" alt="Python versions"></a>
  <a href="https://github.com/morpheuslord/cloudg/actions/workflows/cloudg.yml"><img src="https://github.com/morpheuslord/cloudg/actions/workflows/cloudg.yml/badge.svg" alt="CI"></a>
  <a href="https://morpheuslord.github.io/cloudg/"><img src="https://img.shields.io/badge/docs-GitHub%20Pages-06b6d4" alt="Documentation"></a>
  <a href="https://github.com/morpheuslord/cloudg/blob/main/LICENSE"><img src="https://img.shields.io/pypi/l/cloudg" alt="License: MIT"></a>
</p>

<p align="center"><a href="https://morpheuslord.github.io/cloudg/"><strong>Read the documentation</strong></a> &middot; <a href="https://morpheuslord.github.io/cloudg/sample-report.html">Open the sample report</a></p>

cloudg (cloud graphing) maps AWS, Azure and GCP infrastructure into a graph, runs security scanners over that inventory, and merges every finding into one deduplicated, compliance-mapped result set. It can also skip the scanning entirely and aggregate outputs you already have.

- **Map.** `cloudg map` collects everything deployed (or default) in an account, down to the network fabric, sweeps every service for the rest, and links it all into typed relationships: S3 `INVOKES` Lambda, function `ASSUMES_ROLE` role, WAF `PROTECTS` ALB. No scanner runs and none has to be installed.
- **Scan.** `cloudg run` fans out to Prowler, ScoutSuite, Checkov and Trivy against the same accounts, then normalises, deduplicates and maps every finding against 28 compliance frameworks.
- **Merge.** `cloudg ingest` does the same for scanner output produced elsewhere, with no cloud credentials and no scanner binaries.
- **Use it.** The results leave as an interactive HTML report, JSON, GraphML, an RDF ontology, RAG chunks for LLM pipelines and Terraform files, and `cloudg mcp serve` turns all of it into an MCP server for AI assistants.

## Install

```bash
pip install cloudg            # core: graph, ontology, normaliser, reports, cloudg ingest
pip install "cloudg[aws]"     # plus the AWS SDK
pip install "cloudg[all]"     # every provider SDK and the MCP SDK
```

| Extra | Adds |
|---|---|
| `cloudg[aws]` | boto3 and aioboto3, for collecting from AWS |
| `cloudg[azure]` | The Azure identity and management SDKs, including Resource Graph |
| `cloudg[gcp]` | google-cloud-asset and google-auth, for Cloud Asset Inventory |
| `cloudg[mcp]` | The official MCP SDK (`mcp>=1.30,<3`), for the SDK adapters and HTTP transports |
| `cloudg[all]` | Everything above |

Python 3.11 or newer. The scanners are separate programs, not Python dependencies: install whichever of Prowler, ScoutSuite, Checkov and Trivy you want, and cloudg skips the rest with a warning. The Docker image `ghcr.io/morpheuslord/cloudg` bundles Prowler, Checkov and Trivy. The [installation guide](https://morpheuslord.github.io/cloudg/guides/installation/) has the details.

## Quick start

From the command line:

```bash
# map one AWS account in every enabled region; no scanners involved
cloudg map -p aws --regions all

# collect, scan and report in one go
cloudg run -p aws --regions us-east-1

# already ran the scanners? merge their output, no credentials needed
cloudg ingest --prowler ./prowler-output/ --checkov ./results_json.json --trivy ./trivy.json
```

Reports land in `./reports`. Open `report.html` first, or look at the [sample report](https://morpheuslord.github.io/cloudg/sample-report.html) to see what one looks like.

From Python, the CLI is a thin layer over `CloudGEngine`:

```python
from cloudg import CloudGConfig, CloudGEngine

engine = CloudGEngine(CloudGConfig())
result = engine.run_from_reports_sync(
    {"prowler": ["./prowler-output/"], "trivy": ["./trivy.json"]},
    output_dir="./reports",
)
print(result.total_findings, result.severity_breakdown)
print(result.report_paths)  # findings.json and report.html
```

```python
from cloudg import CloudGConfig, CloudGEngine

config = CloudGConfig(providers=["aws"])
config.aws.regions = ["ALL"]
inventory = CloudGEngine(config).map_inventory_sync(output_dir="./reports")
print(inventory.summary["total_assets"], "assets,", inventory.summary["total_edges"], "edges")
```

## Documentation

The documentation site is at [morpheuslord.github.io/cloudg](https://morpheuslord.github.io/cloudg/):

- [Quickstart](https://morpheuslord.github.io/cloudg/guides/quickstart/) and the [guides](https://morpheuslord.github.io/cloudg/guides/introduction/): authentication, inventory mapping, AWS Organizations, scanners, compliance, reports, Docker and CI.
- [CLI reference](https://morpheuslord.github.io/cloudg/cli/): every command and flag, generated from the code.
- [Python API](https://morpheuslord.github.io/cloudg/api/): `CloudGEngine`, the inventory, graph and findings classes, and the [exceptions](https://morpheuslord.github.io/cloudg/api/exceptions/).
- [Examples](https://morpheuslord.github.io/cloudg/examples/): complete scripts with their output.
- [MCP server](https://morpheuslord.github.io/cloudg/mcp/): connecting Claude Desktop, Claude Code, Cursor or VS Code.
- [config.yaml reference](https://morpheuslord.github.io/cloudg/reference/config/providers/) and the [changelog](https://morpheuslord.github.io/cloudg/changelog/).

The same reference material is kept as Markdown in the repository: the [feature reference](https://github.com/morpheuslord/cloudg/blob/main/docs/DOCUMENTATION.md), the [inventory reference](https://github.com/morpheuslord/cloudg/blob/main/docs/INVENTORY_REFERENCE.md), [catalog](https://github.com/morpheuslord/cloudg/blob/main/docs/INVENTORY_CATALOG.md) and [internals](https://github.com/morpheuslord/cloudg/blob/main/docs/INVENTORY_INTERNALS.md), the [MCP guide](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP.md), [tool reference](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP_TOOLS.md) and [privacy reference](https://github.com/morpheuslord/cloudg/blob/main/docs/MCP_PRIVACY.md), and [rate limits and throttling](https://github.com/morpheuslord/cloudg/blob/main/docs/RESILIENCE.md).

## Credits

cloudg builds on other people's work, and some of it ships inside the package.

[Prowler](https://github.com/prowler-cloud/prowler) (Apache-2.0). The 22 framework files in `cloudg/rules/frameworks/` are generated from Prowler's compliance JSON by `scripts/import_prowler_compliance.py`. That covers the control IDs, the control titles and descriptions, and the mapping from each control to Prowler check names. Every generated file says so in its header and in its `source` field. Prowler check names also appear in `cloudg/rules/check_equivalence.yaml`, and cloudg runs Prowler and parses its ASFF and OCSF output.

Scanners. [Checkov](https://github.com/bridgecrewio/checkov) (Apache-2.0), [Trivy](https://github.com/aquasecurity/trivy) (Apache-2.0) and [ScoutSuite](https://github.com/nccgroup/ScoutSuite) (GPL-2.0) are run as separate programs, and their reports are parsed. Their check IDs (`CKV_*`, `AVD-*`) are used in the check-equivalence map. None of their code is part of cloudg. The Docker image installs Prowler, Checkov and Trivy, so their own licenses apply to those copies.

[Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) (Apache-2.0). The policy packs in `cloudg/policies/` are written in Cloud Custodian's policy format and run with its `custodian` CLI.

[parliament](https://github.com/duo-labs/parliament) (BSD-3-Clause) from Duo Labs does the IAM policy linting.

Drawing engines. The estate map in report.html is drawn with the iso-kit from [Anatomy](https://github.com/wheresryan22/anatomy) (MIT, by Ryan), and its empty states use the kernel of [Hairline](https://hairline.lucasmarkes.com) 0.5.1 (MIT, by Lucas Marques). Both are copied into `cloudg/templates/vendor/` and embedded in every report, so the map works offline. The iso-kit is wrapped so it can sit inside a script element, and `cloudg/templates/vendor/NOTICE` lists exactly what changed.

[MITRE ATT&CK®](https://attack.mitre.org/). The `mitre_attack_*.yaml` files contain ATT&CK technique IDs and descriptions. © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. ATT&CK is a registered trademark of The MITRE Corporation.

Standards. The hand-written rulesets in `cloudg/rules/` reference public control numbering from the CIS Benchmarks for AWS, Azure and GCP, NIST SP 800-53, NIST CSF, PCI DSS, the AICPA SOC 2 Trust Services Criteria, the HIPAA Security Rule, GDPR, ISO/IEC 27001:2022 and the AWS Foundational Security Best Practices. The standards belong to their publishers. CIS Benchmarks is a trademark of the Center for Internet Security, and cloudg is not affiliated with or endorsed by CIS or any other publisher named here.

The Python libraries cloudg depends on (NetworkX, rdflib, pydantic, Click, Rich and the rest) are listed in [`pyproject.toml`](https://github.com/morpheuslord/cloudg/blob/main/pyproject.toml). The full list, with the JavaScript libraries the report embeds, is on the [credits page](https://morpheuslord.github.io/cloudg/credits/).

## License

MIT. See [LICENSE](https://github.com/morpheuslord/cloudg/blob/main/LICENSE).
